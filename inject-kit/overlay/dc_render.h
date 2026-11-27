/* dc_render.h —— DirectComposition + D3D11 + D2D 渲染后端
 *
 * 替代 GDI + 颜色键透明（LWA_COLORKEY）。
 * 窗口需要 WS_EX_NOREDIRECTIONBITMAP（不要 WS_EX_LAYERED，不要 SetLayeredWindowAttributes），
 * DWM 会把 swapchain 当成 GPU 表面合成，不再做全屏颜色键混合。
 */
#pragma once
#include <windows.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef struct CV CV;

/* 生命周期 */
CV*  CV_Create(HWND hwnd);
void CV_Destroy(CV* cv);

/* 每帧：Begin 会按需 resize swapchain，并清成全透明 */
BOOL CV_Begin(CV* cv);
void CV_End(CV* cv);

/* 绘制（颜色 0.0 ~ 1.0） */
void CV_Rect(CV* cv, float l, float t, float r, float b,
             float cr, float cg, float cb, float width);
void CV_FillRect(CV* cv, float l, float t, float r, float b,
                 float cr, float cg, float cb);
void CV_Line(CV* cv, float x0, float y0, float x1, float y1,
             float cr, float cg, float cb, float width);
void CV_Circle(CV* cv, float x, float y, float rad,
               float cr, float cg, float cb, float width);
void CV_Text(CV* cv, float x, float y, const char* s, int len,
             float cr, float cg, float cb);

/* 诊断：最近一次错误描述（失败时返回非空） */
const char* CV_Error(CV* cv);

#ifdef __cplusplus
}   /* extern "C" */
#endif
