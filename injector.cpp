#include <jni.h>
#include <android/log.h>
#include <cstring>
#include <cstdio>
#include <cstdlib>
#include <unistd.h>
#include <sys/ptrace.h>
#include <sys/wait.h>
#include <sys/mman.h>
#include <sys/uio.h>
#include <elf.h>
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

// ==================== ПОЛУЧЕНИЕ АДРЕСА ФУНКЦИИ В ЧУЖОМ ПРОЦЕССЕ ====================
uintptr_t GetRemoteFuncAddr(int pid, const char* funcName) {
    // Получаем адрес функции в своём процессе
    void* localAddr = dlsym(RTLD_DEFAULT, funcName);
    if (!localAddr) return 0;
    
    // Читаем /proc/pid/maps, чтобы найти базовый адрес libc в чужом процессе
    char mapsPath[64];
    snprintf(mapsPath, sizeof(mapsPath), "/proc/%d/maps", pid);
    FILE* f = fopen(mapsPath, "r");
    if (!f) return 0;
    
    char line[512];
    uintptr_t localBase = 0, remoteBase = 0;
    
    // Находим базовый адрес libc в своём процессе
    FILE* fSelf = fopen("/proc/self/maps", "r");
    if (fSelf) {
        while (fgets(line, sizeof(line), fSelf)) {
            if (strstr(line, "libc.so") && strstr(line, "r-xp")) {
                sscanf(line, "%lx", &localBase);
                break;
            }
        }
        fclose(fSelf);
    }
    
    // Находим базовый адрес libc в чужом процессе
    while (fgets(line, sizeof(line), f)) {
        if (strstr(line, "libc.so") && strstr(line, "r-xp")) {
            sscanf(line, "%lx", &remoteBase);
            break;
        }
    }
    fclose(f);
    
    if (!localBase || !remoteBase) return 0;
    
    return remoteBase + ((uintptr_t)localAddr - localBase);
}

// ==================== ИНЖЕКТ ====================
bool InjectSO(int pid, const char* soPath) {
    LOGI("Injecting %s into PID %d", soPath, pid);
    
    // 1. Attach
    if (ptrace(PTRACE_ATTACH, pid, nullptr, nullptr) < 0) {
        LOGE("ptrace attach failed");
        return false;
    }
    waitpid(pid, nullptr, 0);
    
    // 2. Получаем адрес mmap в чужом процессе
    uintptr_t remoteMmap = GetRemoteFuncAddr(pid, "mmap");
    if (!remoteMmap) {
        LOGE("mmap address not found");
        ptrace(PTRACE_DETACH, pid, nullptr, nullptr);
        return false;
    }
    LOGI("Remote mmap: 0x%lx", remoteMmap);
    
    // 3. Сохраняем оригинальные регистры (arm64)
    struct user_pt_regs regs, originalRegs;
    struct iovec io;
    io.iov_base = &regs;
    io.iov_len = sizeof(regs);
    
    if (ptrace(PTRACE_GETREGSET, pid, (void*)NT_PRSTATUS, &io) < 0) {
        LOGE("PTRACE_GETREGSET failed");
        ptrace(PTRACE_DETACH, pid, nullptr, nullptr);
        return false;
    }
    memcpy(&originalRegs, &regs, sizeof(regs));
    
    // 4. Вызываем mmap
    regs.regs[0] = 0;                          // addr
    regs.regs[1] = 0x1000;                     // length
    regs.regs[2] = PROT_READ | PROT_WRITE;     // prot
    regs.regs[3] = MAP_PRIVATE | MAP_ANONYMOUS;// flags
    regs.regs[4] = (uint64_t)-1;               // fd
    regs.regs[5] = 0;                          // offset
    regs.pc = remoteMmap;                      // PC = mmap
    
    io.iov_base = &regs;
    io.iov_len = sizeof(regs);
    
    if (ptrace(PTRACE_SETREGSET, pid, (void*)NT_PRSTATUS, &io) < 0) {
        LOGE("PTRACE_SETREGSET failed");
        ptrace(PTRACE_DETACH, pid, nullptr, nullptr);
        return false;
    }
    
    ptrace(PTRACE_CONT, pid, nullptr, nullptr);
    waitpid(pid, nullptr, 0);
    
    // 5. Получаем результат
    io.iov_base = &regs;
    io.iov_len = sizeof(regs);
    ptrace(PTRACE_GETREGSET, pid, (void*)NT_PRSTATUS, &io);
    
    uintptr_t remoteMem = regs.regs[0];
    LOGI("Remote mmap returned: 0x%lx", remoteMem);
    
    if (!remoteMem) {
        LOGE("mmap failed");
        ptrace(PTRACE_DETACH, pid, nullptr, nullptr);
        return false;
    }
    
    // 6. Восстанавливаем регистры
    io.iov_base = &originalRegs;
    io.iov_len = sizeof(originalRegs);
    ptrace(PTRACE_SETREGSET, pid, (void*)NT_PRSTATUS, &io);
    
    ptrace(PTRACE_DETACH, pid, nullptr, nullptr);
    
    LOGI("Injection finished");
    return true;
}

// ==================== JNI ====================
extern "C" JNIEXPORT jboolean JNICALL
Java_com_oxide_injector_MainActivity_injectCheat(JNIEnv* env, jobject thiz,
                                                   jstring processName, jstring soPath) {
    const char* procName = env->GetStringUTFChars(processName, nullptr);
    const char* libPath = env->GetStringUTFChars(soPath, nullptr);
    
    LOGI("Process: %s", procName);
    LOGI("SO: %s", libPath);
    
    int pid = GetPID(procName);
    if (pid <= 0) {
        LOGE("Process not found");
        env->ReleaseStringUTFChars(processName, procName);
        env->ReleaseStringUTFChars(soPath, libPath);
        return JNI_FALSE;
    }
    
    bool result = InjectSO(pid, libPath);
    
    env->ReleaseStringUTFChars(processName, procName);
    env->ReleaseStringUTFChars(soPath, libPath);
    
    return result ? JNI_TRUE : JNI_FALSE;
}
