#include <objc/runtime.h>
#include <dlfcn.h>
#include <stdio.h>
#include <substitute.h>
#include <os/log.h>

#ifdef __cplusplus
extern "C" {
#endif

bool MSDebug = true;

#ifdef __cplusplus
}
#endif

char* GetAddrInfo(void* addr){
    Dl_info info;
    ssize_t size = 0;
    char* buf = NULL;

    if(dladdr(addr, &info)){
        size = snprintf(NULL, 0, "%s (0x%lx)`%s + %ld", info.dli_fname, addr - info.dli_fbase, info.dli_sname, addr - info.dli_saddr);
        buf = malloc(size + 1);
        snprintf(buf, size + 1, "%s (0x%lx)`%s + %ld", info.dli_fname, addr - info.dli_fbase, info.dli_sname, addr - info.dli_saddr);
    }else{
        size = snprintf(NULL, 0, "%p symbol not found", addr);
        buf = malloc(size + 1);
        snprintf(buf, size + 1, "%p symbol not found", addr);
    }
    return buf;
}

extern void *SubGetImageByName(const char *filename) __asm__("SubGetImageByName");;
void *MSGetImageByName(const char *filename) {
    void* image = SubGetImageByName(filename);
    if(MSDebug){
        os_log_debug(OS_LOG_DEFAULT, "libsubstrate-shim: MSGetImageByName: %{public}s, image: %p; called from %{public}s", filename, image, GetAddrInfo(__builtin_return_address(0)));
    }
    return image;
}

extern void *SubFindSymbol(void *image, const char *name) __asm__("SubFindSymbol");
void *MSFindSymbol(void *image, const char *name) {
    void* symbol = SubFindSymbol(image, name);
    if(MSDebug){
        os_log_debug(OS_LOG_DEFAULT, "libsubstrate-shim: MSFindSymbol: %p, %{public}s, symbol: %{public}s; called from %{public}s", image, name, GetAddrInfo(symbol), GetAddrInfo(__builtin_return_address(0)));
    }
	return symbol;
}

extern void SubHookFunction(void *symbol, void *replace, void **result) __asm__("SubHookFunction");
void MSHookFunction(void *symbol, void *replace, void **result) {
    if(MSDebug){
        os_log_debug(OS_LOG_DEFAULT, "libsubstrate-shim: MSHookFunction: %{public}s, %{public}s, %{public}s; called from %{public}s", GetAddrInfo(symbol), GetAddrInfo(replace), GetAddrInfo(result), GetAddrInfo(__builtin_return_address(0)));
    }
	SubHookFunction(symbol, replace, result);
}

extern void SubHookMessageEx(Class _class, SEL sel, IMP imp, IMP *result) __asm__("SubHookMessageEx");
void MSHookMessageEx(Class _class, SEL sel, IMP imp, IMP *result) {
    if(MSDebug){
        os_log_debug(OS_LOG_DEFAULT, "libsubstrate-shim: MSHookMessageEx: %{public}s, %{public}s, %{public}s, %{public}s; called from %{public}s", class_getName(_class), sel_getName(sel), GetAddrInfo(imp), GetAddrInfo(result), GetAddrInfo(__builtin_return_address(0)));
    }
	if (class_getInstanceMethod(_class, sel) || class_getClassMethod(_class, sel)) {
		SubHookMessageEx(_class, sel, imp, result);
	} else {
		os_log_error(OS_LOG_DEFAULT, "libsubstrate-shim: Tried to hook non-existent selector %{public}s on class %{public}s",
			sel_getName(sel), class_getName(_class));
			if (result) *result = NULL;
	}
}

// i don't think anyone uses this function anymore, but it's here for completeness
void MSHookClassPair(Class _class, Class hook, Class old) {
    unsigned int n_methods = 0;
    Method *hooks = class_copyMethodList(hook, &n_methods);
    
    for (unsigned int i = 0; i < n_methods; ++i) {
        SEL selector = method_getName(hooks[i]);
        const char *what = method_getTypeEncoding(hooks[i]);
        
        Method old_mptr = class_getInstanceMethod(old, selector);
        Method cls_mptr = class_getInstanceMethod(_class, selector);
        
        if (cls_mptr) {
            class_addMethod(old, selector, method_getImplementation(hooks[i]), what);
            method_exchangeImplementations(cls_mptr, old_mptr);
        } else {
            class_addMethod(_class, selector, method_getImplementation(hooks[i]), what);
        }
    }
    
    free(hooks);
}
