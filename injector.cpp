#include <jni.h>
#include <android/log.h>
#include <cstring>
#include <cstdio>
#include <cstdlib>
#include <unistd.h>
#include <sys/ptrace.h>
#include <sys/wait.h>
#include <sys/mman.h>
#include <dlfcn.h>
#include <dirent.h>
#include <string>
#include <fstream>

#define LOG_TAG "OxideInjector"
#define LOGI(...) __android_log_print(ANDROID_LOG_INFO, LOG_TAG, __VA_ARGS__)
#define LOGE(...) __android_log_print(ANDROID_LOG_ERROR, LOG_TAG, __VA_ARGS__)

// ==================== ПОИСК PID ====================
int GetPID(const char* processName) {
    DIR* dir = opendir("/proc");
    if (!dir) return -1;
    
    struct dirent* entry;
    while ((entry = readdir(dir)) != nullptr) {
        if (entry->d_type != DT_DIR) continue;
        
        int pid = atoi(entry->d_name);
        if (pid <= 0) continue;
        
        char cmdlinePath[64];
        snprintf(cmdlinePath, sizeof(cmdlinePath), "/proc/%d/cmdline", pid);
        
        FILE* f = fopen(cmdlinePath, "r");
        if (!f) continue;
        
        char cmdline[256] = {0};
        fread(cmdline, 1, sizeof(cmdline) - 1, f);
        fclose(f);
        
        if (strstr(cmdline, processName) != nullptr) {
            closedir(dir);
            return pid;
        }
    }
    closedir(dir);
    return -1;
}

// ==================== ИНЖЕКТ ЧЕРЕЗ PTRACE ====================
bool InjectSO(int pid, const char* soPath) {
    LOGI("Injecting %s into PID %d", soPath, pid);
    
    // 1. Attach к процессу
    if (ptrace(PTRACE_ATTACH, pid, nullptr, nullptr) < 0) {
        LOGE("ptrace attach failed");
        return false;
    }
    waitpid(pid, nullptr, 0);
    
    // 2. Сохраняем оригинальные регистры
    struct pt_regs regs, originalRegs;
    if (ptrace(PTRACE_GETREGS, pid, nullptr, &regs) < 0) {
        LOGE("ptrace getregs failed");
        ptrace(PTRACE_DETACH, pid, nullptr, nullptr);
        return false;
    }
    memcpy(&originalRegs, &regs, sizeof(regs));
    
    // 3. Находим адрес mmap в libc
    void* mmapAddr = (void*)dlsym(RTLD_DEFAULT, "mmap");
    if (!mmapAddr) {
        LOGE("mmap not found");
        ptrace(PTRACE_DETACH, pid, nullptr, nullptr);
        return false;
    }
    
    // 4. Вызываем mmap в чужом процессе
    regs.ARM_r0 = 0;                    // addr = NULL
    regs.ARM_r1 = 0x1000;               // length = 4096
    regs.ARM_r2 = PROT_READ | PROT_WRITE | PROT_EXEC;
    regs.ARM_r3 = MAP_PRIVATE | MAP_ANONYMOUS;
    regs.ARM_r4 = -1;                   // fd
    regs.ARM_r5 = 0;                    // offset
    regs.ARM_pc = (uint32_t)mmapAddr;
    
    if (ptrace(PTRACE_SETREGS, pid, nullptr, &regs) < 0) {
        LOGE("ptrace setregs failed (mmap)");
        ptrace(PTRACE_DETACH, pid, nullptr, nullptr);
        return false;
    }
    ptrace(PTRACE_CONT, pid, nullptr, nullptr);
    waitpid(pid, nullptr, 0);
    
    // 5. Получаем результат mmap
    ptrace(PTRACE_GETREGS, pid, nullptr, &regs);
    uintptr_t remoteMapAddr = regs.ARM_r0;
    if (!remoteMapAddr) {
        LOGE("mmap returned NULL");
        ptrace(PTRACE_DETACH, pid, nullptr, nullptr);
        return false;
    }
    
    // 6. Записываем путь к .so в чужой процесс
    std::ifstream file(soPath, std::ios::binary);
    if (!file) {
        LOGE("Cannot open %s", soPath);
        ptrace(PTRACE_DETACH, pid, nullptr, nullptr);
        return false;
    }
    
    std::string soData((std::istreambuf_iterator<char>(file)),
                        std::istreambuf_iterator<char>());
    file.close();
    
    for (size_t i = 0; i < soData.size(); i += 4) {
        uint32_t word = 0;
        memcpy(&word, soData.data() + i, 4);
        if (ptrace(PTRACE_POKETEXT, pid, remoteMapAddr + i, word) < 0) {
            LOGE("ptrace poketext failed");
            ptrace(PTRACE_DETACH, pid, nullptr, nullptr);
            return false;
        }
    }
    
    // 7. Восстанавливаем регистры
    ptrace(PTRACE_SETREGS, pid, nullptr, &originalRegs);
    
    // 8. Detach
    ptrace(PTRACE_DETACH, pid, nullptr, nullptr);
    
    LOGI("Injection complete!");
    return true;
}

// ==================== JNI ====================
extern "C" JNIEXPORT jboolean JNICALL
Java_com_oxide_injector_MainActivity_injectCheat(JNIEnv* env, jobject thiz,
                                                   jstring processName, jstring soPath) {
    const char* procName = env->GetStringUTFChars(processName, nullptr);
    const char* libPath = env->GetStringUTFChars(soPath, nullptr);
    
    LOGI("Looking for process: %s", procName);
    
    int pid = GetPID(procName);
    if (pid <= 0) {
        LOGE("Process %s not found", procName);
        env->ReleaseStringUTFChars(processName, procName);
        env->ReleaseStringUTFChars(soPath, libPath);
        return JNI_FALSE;
    }
    
    LOGI("Found PID: %d", pid);
    
    bool result = InjectSO(pid, libPath);
    
    env->ReleaseStringUTFChars(processName, procName);
    env->ReleaseStringUTFChars(soPath, libPath);
    
    return result ? JNI_TRUE : JNI_FALSE;
}
