LOCAL_PATH := $(call my-dir)
include $(CLEAR_VARS)
LOCAL_MODULE := injector
LOCAL_SRC_FILES := injector.cpp
LOCAL_LDLIBS := -llog -ldl
include $(BUILD_SHARED_LIBRARY)
