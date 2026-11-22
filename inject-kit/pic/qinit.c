typedef unsigned __int64 U64;
typedef unsigned int U32;

typedef struct _TABLE {
    U64 stage;          /* 0x00 */
    U64 origQpc;        /* 0x08 */
    U64 count;          /* 0x10 */
    U64 iid[2];         /* 0x18 */
    U64 hitObj;         /* 0x28 */
    U64 hitVt;          /* 0x30 */
    U64 hitOk;          /* 0x38 */
    U64 cand[40];       /* 0x40 */
    U64 swapObj[8];     /* 0x180 all QI-matching swapchains */
    U64 swapVt[8];      /* 0x1C0 */
    U64 swapCount;      /* 0x200 */
} TABLE;

__declspec(dllexport, noinline) void QInit(TABLE* t)
{
    U64 i;

    for (i = 0; i < t->count && i < 40; i++) {
        void* obj = (void*)t->cand[i];
        void** vt;
        void* out = 0;
        long hr;

        if (!obj) continue;
        vt = *(void***)obj;
        hr = ((long(__stdcall*)(void*, const void*, void**))vt[0])(obj, t->iid, &out);
        if (hr == 0) {
            if (t->swapCount < 8) {
                t->swapObj[t->swapCount] = (U64)obj;
                t->swapVt[t->swapCount] = (U64)(U64)vt;
                t->swapCount++;
            }
            if (out) ((unsigned long(__stdcall*)(void*))vt[2])(out);
            if (t->hitObj == 0) { t->hitObj = (U64)obj; t->hitVt = (U64)(U64)vt; }
        }
    }
    t->hitOk = 2;
}
