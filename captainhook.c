/*
 * This is free and unencumbered software released into the public domain.
 * see the attached UNLICENSE or http://unlicense.org/
 */

#include <android/log.h>
#include <dlfcn.h>
#include <sys/mman.h>
#include <sys/sysconf.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <link.h>
#include <errno.h>

#define LOG_MAX 2048

void log_n(char* s, int n) {
  char buf[LOG_MAX + 1];
  char *p, *end;
  for (p = s, end  = p + n; p < end; p += LOG_MAX) {
    int len = end - p;
    len = len > LOG_MAX ? LOG_MAX : len;
    memcpy(buf, p, len);
    buf[len] = 0;
    __android_log_write(ANDROID_LOG_DEBUG, __FILE__, buf);
  }
}

void log_s(char* s) { log_n(s, strlen(s)); }
void (*_JNI_OnLoad)(void* env);

/*
  make memory readadable, writable and executable. size is
  ceiled to a multiple of PAGESIZE and addr is aligned to
  PAGESIZE
*/
#define PROT_RWX (PROT_READ | PROT_WRITE | PROT_EXEC)
#define PAGESIZE sysconf(_SC_PAGESIZE)
#define PAGEOF(addr) (void*)((int)(addr) & ~(PAGESIZE - 1))
#define PAGE_ROUND_UP(x) \
    ((((int)(x)) + PAGESIZE - 1) & (~(PAGESIZE - 1)))
#define munprotect(addr, n) \
    mprotect(PAGEOF(addr), PAGE_ROUND_UP(n), PROT_RWX)

typedef struct {
  void* vtable;
  void* unknown;
  int Length;
  unsigned short Data[1]; /* UTF-16LE, actually Length elements */
} String;

/* truncate to ascii. good enough for now */
static
char* String_to_c(String* str) {
  int i;
  char* buf = malloc(str->Length + 1);
  for (i = 0; i < str->Length; ++i) {
    buf[i] = (char)str->Data[i];
  }
  buf[str->Length] = 0;
  return buf;
}

static
void String_log(String* str) {
  char* buf = String_to_c(str);
  log_n(buf, str->Length);
  free(buf);
}

typedef struct {
  void* vtable;
  void* unknown[2];
  int Length;
  char Data[1];
} Array;

static
void Array_log_ascii(Array* arr) {
  char* buf;
  if (!arr) {
    log_s("(null array)");
    return;
  }
  buf = malloc(arr->Length + 1);
  if (!buf) {
    log_s("(empty array or OOM)");
    return;
  }
  memcpy(buf, arr->Data, arr->Length);
  buf[arr->Length] = 0;
  log_n(buf, arr->Length);
  free(buf);
}

/* --------------------------------------------------------------------- */

typedef struct {
  void* vtable;
  void* unknown;
  void* Headers; /* dictionary */
  int Status;
  String* Text;
  Array* Bytes;
  void* Texture;
  String* Bundle;
  String* ErrorText;
  void* Exception;
} HTTPResponse;

static
void HTTPResponse_log(HTTPResponse* resp) {
  if (resp->Text) {
    String_log(resp->Text);
  } else {
    /* TODO: detect and parse msgpack */
    Array_log_ascii(resp->Bytes);
  }
}

static String* (*original_get_Text)(HTTPResponse* resp);

static
String* hooked_get_Text(HTTPResponse* resp) {
  HTTPResponse_log(resp);
  return original_get_Text(resp);
}

static Array* (*original_get_Bytes)(HTTPResponse* resp);

static
Array* hooked_get_Bytes(HTTPResponse* resp) {
  HTTPResponse_log(resp);
  return original_get_Bytes(resp);
}

/* --------------------------------------------------------------------- */

typedef struct {
  void* vtable;
  void* unknown;
  char isUnixFilePath;
  String* source;
  String* scheme;
  String* host;
  int port;
  String* path;
  String* query;
  String* fragment;
  String* userinfo;
  char isUnc;
  char isOpaquePart;
  char isAbsoluteUri;
  Array* segments; /* array of String* */
  char userEscaped;
  String* cachedAbsoluteUri;
  String* cachedToString;
  String* cachedLocalPath;
  int cachedHashCode;
  void* parser; /* UriParser */
} Uri;

#define Method_Post 3

typedef struct {
  void* vtable;
  void* unknown;
  Uri* Uri;
  int Method;
  int Type;
  void* ResponseHandler;
  void* ErrorHandler;
  void* ProgressHandler;
  char Sync;
  char Stub;
  String* FileName;
  void* Proxy; /* might be a string, not sure */
  int Timeout;
  int RetryCount;
  int ProgressInterval;
  String* BundleVersion;
  void* Headers; /* Dictionary */
  void* Bodies; /* Dictionary */
  void* Attributes; /* Jackpot.Memory, seems to just be a dict */
  Array* RawBody;
} HTTPRequest;

static void (*original_SetHeader)(HTTPRequest*, String*, String*);

static void hooked_SetHeader(HTTPRequest* req, String* sk, String* sv) {
  char* k = String_to_c(sk);
  char* v = String_to_c(sv);
  char* buf = malloc(strlen(k) + strlen(v) + 3);
  sprintf(buf, "%s: %s", k, v);
  log_s(buf);
  free(buf);
  free(k);
  free(v);
  return original_SetHeader(req, sk, sv);
}

static void (*original_set_ResponseHandler)(HTTPRequest*, void*);

static void hooked_set_ResponseHandler(HTTPRequest* req, void* handler) {
  String_log(req->Uri->source);
  Array_log_ascii(req->RawBody);
  original_set_ResponseHandler(req, handler);
}

/* --------------------------------------------------------------------- */

#define THUMB (1<<1)

static
void hook(char* name, char* addr, void** ptrampoline, void* dst, int fl) {
  char buf[512];
  int i;
  char *p;
  unsigned* code;

  unsigned absolute_jump =
    (fl & THUMB) ?
      0xF000F8DF:  /* thumb mode: ldr pc,[pc]     */
      0xE51FF004;  /*   arm mode: ldr pc,[pc,#-4] */

  p = buf;
  p += sprintf(p, "%s at %p: ", name, addr);
  for (i = 0; i < 8; ++i) {
    p += sprintf(p, "%02x ", addr[i]);
  }
  log_s(buf);
  sprintf(buf, "-> %p", dst);
  log_s(buf);

  /*
   * alloc a trampoline to call the original function.
   * it's a copy of the instructions we overwrote followed by a jmp to
   * right after where hook jump will be in the original function
   * again using an abosolute jump like in the asm trampolines
   */
  *ptrampoline = malloc(8 + 8);
  code = (unsigned*)*ptrampoline;
  munprotect(code, 8 + 8);
  memcpy(code, addr, 8);
  code[2] = absolute_jump;
  code[3] = (unsigned)addr + 8;

  /*
   * overwrite the original function's first 8 bytes with an absolute jump
   * to our hook
   */
  code = (unsigned*)addr;
  munprotect(code, 8);
  code[0] = absolute_jump;
  code[1] = (unsigned)dst;
}

typedef struct {
  unsigned magic;
  int version;
  int strings;
  int strings_size;
  int string_data;
  int string_data_size;
  int metadata_strings;
  int metadata_strings_size;
  int events;
  int events_size;
  int properties;
  int properties_size;
  int methods;
  int methods_size;
} __attribute__((packed))
il2cpp_metadata_header_t;

typedef struct {
  int name; /* index into metadata strings, null terminated */
  int declaring_type;
  int return_type;
  int parameter_start;
  int custom_attrib;
  int generic_container;
  int index; /* index into methods table */
  int invoker_index;
  int delegate_wrapper_index;
  int rgctx_start_index;
  int rgctx_count;
  unsigned token;
  unsigned short flags;
  unsigned short iflags;
  unsigned short slot;
  unsigned short num_parameters;
} __attribute__((packed))
il2cpp_method_definition_t;

typedef struct {
  int method_pointers_size;
  unsigned* method_pointers;
} __attribute__((packed))
il2cpp_code_registration_t;

typedef struct {
  il2cpp_code_registration_t* code_reg;
  unsigned table;
} scan_result_t;

unsigned char pattern_v21[] = {
  0x02, 0x10, 0x91, 0xe7, /* ldr r1, [r1,r2] */
  0x02, 0x00, 0x8c, 0xe0, /* add r0, r12, r2 */
  0x02, 0x20, 0x83, 0xe0 /* add r2, r3, r2 */
};

static
int phdr_callback(struct dl_phdr_info* info, size_t size, void* data) {
  scan_result_t* scan = data;
  int i;
  char buf[512];
  if (!strstr(info->dlpi_name, "libil2cpp.so")) return 0;
  sprintf(buf, "il2cpp at %08x", info->dlpi_addr);
  log_s(buf);
  for (i = 0; !scan->table && i < info->dlpi_phnum; ++i) {
    Elf32_Phdr const* hdr = &info->dlpi_phdr[i];
    Elf32_Dyn* dyn = (Elf32_Dyn*)(info->dlpi_addr + hdr->p_vaddr);
    if (hdr->p_type == PT_DYNAMIC) {
      sprintf(buf, "PT_DYNAMIC is header %2d at %10p", i, dyn);
      log_s(buf);
      for (; dyn->d_tag != DT_NULL; ++dyn) {
        if (dyn->d_tag == DT_PLTGOT) {
          scan->table = dyn->d_un.d_ptr;
          sprintf(buf, "_GLOBAL_OFFSET_TABLE_ at %08x", dyn->d_un.d_ptr);
          log_s(buf);
        }
      }
    }
  }
  for (i = 0; i < info->dlpi_phnum; ++i) {
    Elf32_Phdr const* hdr = &info->dlpi_phdr[i];
    Elf32_Addr start = hdr->p_vaddr;
    Elf32_Addr end = hdr->p_vaddr + hdr->p_memsz;
    if (hdr->p_type != PT_LOAD) continue;
    if (!(hdr->p_flags & PF_X)) continue;
    Elf32_Addr p;
    for (p = start; p <= end - sizeof(pattern_v21); p += 1) {
      if (!memcmp(pattern_v21, (char*)info->dlpi_addr + p, sizeof(pattern_v21))) {
        /* this is unreadable but it works trust me */
        Elf32_Addr code_registration =
          *(Elf32_Addr*)(info->dlpi_addr + p + 0x14) +
          scan->table;
        Elf32_Addr metadata_registration =
          *(Elf32_Addr*)(
            info->dlpi_addr +
            *(Elf32_Addr*)(info->dlpi_addr + p + 0x18)
            + scan->table
          ) - info->dlpi_addr;
        sprintf(buf, "code registration: %08x | "
          " metadata registration: %08x",
          code_registration, metadata_registration);
        log_s(buf);
        scan->code_reg = (void*)(info->dlpi_addr + code_registration);
        return 0;
      }
    }
  }
  return 0;
}

static
void hook_from_metadata() {
  char buf[512], buf2[512];
  char const* p;
  char* dst;
  Dl_info dli;
  FILE* f;
  int i, num_methods;
  il2cpp_metadata_header_t hdr;
  il2cpp_method_definition_t* methods = 0;
  scan_result_t scan = {0};
  unsigned* method_pointers;
  unsigned last_get_Text;
  char* metadata_strings = 0;
  if (!dladdr(hook_from_metadata, &dli)) {
    log_s("failed to get own path");
  }
  /* android x86 path */
  /* /data/app/com.klab.lovelive.allstars-mi_.../lib/arm/....so */
  sprintf(buf, "running as %s\n", dli.dli_fname);
  log_s(buf);
  for (p = dli.dli_fname; *p && strstr(p, "com.") != p; ++p);
  /* com.klab.lovelive.allstars-mi_.../lib/arm/....so */
  for (dst = buf; *p && *p != '-'; *dst++ = *p++);
  *dst = 0;
  /* com.klab.lovelive.allstars */
  sprintf(buf2,
    "/data/data/%s/files/il2cpp/Metadata/global-metadata.dat", buf);
  log_s(buf2);
  f = fopen(buf2, "rb");
  if (!f) {
    /* on bluestacks it seems to have this different path. maybe on
     * real device as well */
    sprintf(buf2, "/data/media/0/Android/data/%s/files"
      "/il2cpp/Metadata/global-metadata.dat", buf);
    log_s(buf2);
    f = fopen(buf2, "rb");
  }
  if (!f) {
    log_s(strerror(errno));
    log_s("failed to open metadata file");
    return;
  }
  if (fread(&hdr, sizeof(hdr), 1, f) != 1) {
    log_s("failed to read metadata header");
    goto cleanup;
  }
  if (hdr.magic != 0xFAB11BAF) {
    log_s("not a valid metadata file");
    goto cleanup;
  }
  sprintf(buf, "metadata version %d", hdr.version);
  log_s(buf);
  if (fseek(f, hdr.methods, SEEK_SET)) {
    log_s("failed to seek to methods table");
    goto cleanup;
  }
  methods = malloc(hdr.methods_size);
  if (!methods) {
    log_s("failed to alloc method table");
    goto cleanup;
  }
  if (fread(methods, hdr.methods_size, 1, f) != 1) {
    log_s("failed to read method table");
    goto cleanup;
  }
  dl_iterate_phdr(phdr_callback, &scan);
  if (!scan.code_reg) {
    log_s("failed to find code registration");
    goto cleanup;
  }
  num_methods = hdr.methods_size / sizeof(il2cpp_method_definition_t);
  method_pointers = scan.code_reg->method_pointers;
  metadata_strings = malloc(hdr.metadata_strings_size);
  if (!metadata_strings) {
    log_s("failed to alloc metadata strings");
    goto cleanup;
  }
  if (fseek(f, hdr.metadata_strings, SEEK_SET)) {
    log_s("failed to seek to metadata strings");
    goto cleanup;
  }
  if (fread(metadata_strings, hdr.metadata_strings_size, 1, f) != 1) {
    log_s("failed to read metadata strings");
    goto cleanup;
  }
  sprintf(buf, "%d methods", num_methods);
  log_s(buf);
  for (i = 0; i < num_methods; ++i) {
    char* name = metadata_strings + methods[i].name;
    if (methods[i].index >= 0) {
      /* TODO: generic methods */
      /* TODO: get class name for better reliability */
#define h(name) \
  if (!original_##name) { \
    hook(#name, (char*)method_pointers[methods[i].index], \
      (void**)&original_##name, hooked_##name, 0); \
  }
      /* HTTPRequest$$set_ResponseHandler */
      if (!strcmp(name, "set_ResponseHandler")) { h(set_ResponseHandler) }
      /* HTTPResponse$$get_Text slightly before get_Bytes */
      else if (!strcmp(name, "get_Text")) {
        last_get_Text = method_pointers[methods[i].index];
      }
      /* HTTPResponse$$get_Bytes */
      else if (!strcmp(name, "get_Bytes")) {
        if (!original_get_Bytes) {
          hook("get_Text", (char*)last_get_Text,
            (void**)&original_get_Text, hooked_get_Text, 0);
          h(get_Bytes)
        }
      }
      /* HTTPRequest$$GetHeader */
      else if (!strcmp(name, "SetHeader")) h(SetHeader)
#undef h
    }
  }
cleanup:
  free(metadata_strings);
  free(methods);
  fclose(f);
}

static
void init() {
  void *original, *stub;
  log_s("hello from the stub library!");
  dlopen("libil2cpp.so", RTLD_LAZY);
  original = dlopen("libmain.so.bak", RTLD_LAZY);
  stub = dlopen("libmain.so", RTLD_LAZY);
  *(void**)&_JNI_OnLoad = dlsym(original, "JNI_OnLoad");
  hook_from_metadata();
}

void JNI_OnLoad(void* env) {
  init();
  _JNI_OnLoad(env);
}
