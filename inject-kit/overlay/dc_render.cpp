/* dc_render.c —— DirectComposition + D3D11 + D2D 渲染后端实现 */
#include "dc_render.h"

#include <stdio.h>

#include <d3d11.h>
#include <dxgi1_3.h>
#include <d2d1_1.h>
#include <d2d1helper.h>
#include <dcomp.h>
#include <dwrite.h>

#pragma comment(lib, "d3d11.lib")
#pragma comment(lib, "dxgi.lib")
#pragma comment(lib, "d2d1.lib")
#pragma comment(lib, "dcomp.lib")
#pragma comment(lib, "dwrite.lib")

struct CV {
    HWND                 hwnd;
    ID3D11Device*        dev;
    ID3D11DeviceContext* ctx;
    IDXGISwapChain1*     swap;
    ID2D1Factory1*       d2dFactory;
    ID2D1Device*         d2dDevice;
    ID2D1DeviceContext*  d2dCtx;
    ID2D1Bitmap1*        target;
    ID2D1SolidColorBrush* brush;
    ID2D1StrokeStyle*    stroke;
    IDCompositionDevice* dcomp;
    IDCompositionTarget* dcTarget;
    IDCompositionVisual* dcVisual;
    IDWriteFactory*      dwFactory;
    IDWriteTextFormat*   txtFmt;
    UINT                 width;
    UINT                 height;
    char                 err[256];
};

static void seterr(CV* cv, const char* what, HRESULT hr)
{
    _snprintf_s(cv->err, sizeof(cv->err), _TRUNCATE, "%s hr=0x%08lX", what, (unsigned long)hr);
}

static void destroy_target(CV* cv)
{
    if (cv->target)   { cv->target->Release();   cv->target = NULL; }
}

static void destroy_size(CV* cv)
{
    destroy_target(cv);
    if (cv->swap)     { cv->swap->Release();     cv->swap = NULL; }
    if (cv->dcVisual) { cv->dcVisual->Release(); cv->dcVisual = NULL; }
    if (cv->dcTarget) { cv->dcTarget->Release(); cv->dcTarget = NULL; }
}

/* 创建/重建 swapchain + DComp 视觉树 */
static BOOL build_size(CV* cv, UINT w, UINT h)
{
    HRESULT hr;
    DXGI_SWAP_CHAIN_DESC1 d;
    IDXGIDevice* dxgiDev = NULL;
    IDXGIAdapter* adapter = NULL;
    IDXGIFactory2* factory = NULL;

    destroy_size(cv);
    if (w == 0 || h == 0) return TRUE;      /* 窗口最小化：什么都不做 */

    RtlZeroMemory(&d, sizeof(d));
    d.Width              = w;
    d.Height             = h;
    d.Format             = DXGI_FORMAT_B8G8R8A8_UNORM;
    d.Stereo             = FALSE;
    d.SampleDesc.Count   = 1;
    d.BufferUsage        = DXGI_USAGE_RENDER_TARGET_OUTPUT;
    d.BufferCount        = 2;
    d.Scaling            = DXGI_SCALING_STRETCH;
    d.SwapEffect         = DXGI_SWAP_EFFECT_FLIP_SEQUENTIAL;
    d.AlphaMode          = DXGI_ALPHA_MODE_PREMULTIPLIED;   /* 关键：走 DWM GPU 合成 */
    d.Flags              = 0;

    hr = cv->dev->QueryInterface(__uuidof(IDXGIDevice), (void**)&dxgiDev);
    if (FAILED(hr)) { seterr(cv, "QI IDXGIDevice", hr); goto fail; }
    hr = dxgiDev->GetAdapter(&adapter);
    if (FAILED(hr)) { seterr(cv, "GetAdapter", hr); goto fail; }
    hr = adapter->GetParent(__uuidof(IDXGIFactory2), (void**)&factory);
    if (FAILED(hr)) { seterr(cv, "GetParent IFactory2", hr); goto fail; }

    hr = factory->CreateSwapChainForComposition(cv->dev, &d, NULL, &cv->swap);
    if (FAILED(hr)) { seterr(cv, "CreateSwapChainForComposition", hr); goto fail; }

    hr = cv->dcomp->CreateVisual(&cv->dcVisual);
    if (FAILED(hr)) { seterr(cv, "DComp CreateVisual", hr); goto fail; }
    cv->dcVisual->SetContent(cv->swap);

    hr = cv->dcomp->CreateTargetForHwnd(cv->hwnd, TRUE, &cv->dcTarget);
    if (FAILED(hr)) { seterr(cv, "DComp CreateTargetForHwnd", hr); goto fail; }
    cv->dcTarget->SetRoot(cv->dcVisual);
    cv->dcomp->Commit();

    /* D2D 渲染目标绑到 back buffer */
    {
        IDXGISurface* surf = NULL;
        D2D1_BITMAP_PROPERTIES1 bp;
        hr = cv->swap->GetBuffer(0, __uuidof(IDXGISurface), (void**)&surf);
        if (FAILED(hr)) { seterr(cv, "GetBuffer", hr); goto fail; }
        RtlZeroMemory(&bp, sizeof(bp));
        bp.pixelFormat.format    = DXGI_FORMAT_B8G8R8A8_UNORM;
        bp.pixelFormat.alphaMode = D2D1_ALPHA_MODE_PREMULTIPLIED;
        bp.bitmapOptions         = D2D1_BITMAP_OPTIONS_TARGET | D2D1_BITMAP_OPTIONS_CANNOT_DRAW;
        hr = cv->d2dCtx->CreateBitmapFromDxgiSurface(surf, &bp, &cv->target);
        surf->Release();
        if (FAILED(hr)) { seterr(cv, "CreateBitmapFromDxgiSurface", hr); goto fail; }
        cv->d2dCtx->SetTarget(cv->target);
    }

    cv->width  = w;
    cv->height = h;
    factory->Release();
    adapter->Release();
    dxgiDev->Release();
    return TRUE;

fail:
    if (factory) factory->Release();
    if (adapter) adapter->Release();
    if (dxgiDev) dxgiDev->Release();
    return FALSE;
}

CV* CV_Create(HWND hwnd)
{
    CV* cv;
    HRESULT hr;
    D3D_FEATURE_LEVEL lvl[] = { D3D_FEATURE_LEVEL_11_1, D3D_FEATURE_LEVEL_11_0 };
    D3D_FEATURE_LEVEL got;
    UINT flags = D3D11_CREATE_DEVICE_BGRA_SUPPORT;
    IDXGIDevice* dxgiDev = NULL;
    D2D1_FACTORY_OPTIONS fo;

    cv = (CV*)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, sizeof(CV));
    if (!cv) return NULL;
    cv->hwnd = hwnd;

    /* D3D11 设备（BGRA 支持是 D2D 互通的前提） */
    hr = D3D11CreateDevice(NULL, D3D_DRIVER_TYPE_HARDWARE, NULL, flags,
                           lvl, 2, D3D11_SDK_VERSION,
                           &cv->dev, &got, &cv->ctx);
    if (FAILED(hr)) { seterr(cv, "D3D11CreateDevice", hr); return cv; }

    /* D2D */
    RtlZeroMemory(&fo, sizeof(fo));
    hr = D2D1CreateFactory(D2D1_FACTORY_TYPE_SINGLE_THREADED,
                           __uuidof(ID2D1Factory1), &fo, (void**)&cv->d2dFactory);
    if (FAILED(hr)) { seterr(cv, "D2D1CreateFactory", hr); return cv; }

    hr = cv->dev->QueryInterface(__uuidof(IDXGIDevice), (void**)&dxgiDev);
    if (FAILED(hr)) { seterr(cv, "QI IDXGIDevice", hr); return cv; }

    hr = cv->d2dFactory->CreateDevice(dxgiDev, &cv->d2dDevice);
    if (FAILED(hr)) { seterr(cv, "D2D CreateDevice", hr); dxgiDev->Release(); return cv; }

    hr = cv->d2dDevice->CreateDeviceContext(D2D1_DEVICE_CONTEXT_OPTIONS_NONE, &cv->d2dCtx);
    if (FAILED(hr)) { seterr(cv, "D2D CreateDeviceContext", hr); dxgiDev->Release(); return cv; }

    /* DirectComposition */
    hr = DCompositionCreateDevice(dxgiDev, __uuidof(IDCompositionDevice), (void**)&cv->dcomp);
    dxgiDev->Release();
    if (FAILED(hr)) { seterr(cv, "DCompositionCreateDevice", hr); return cv; }

    /* 画刷 + 描边样式 */
    hr = cv->d2dCtx->CreateSolidColorBrush(
            D2D1::ColorF(1, 1, 1, 1), &cv->brush);
    if (FAILED(hr)) { seterr(cv, "CreateSolidColorBrush", hr); return cv; }

    {
        D2D1_STROKE_STYLE_PROPERTIES sp = D2D1::StrokeStyleProperties();
        sp.startCap = D2D1_CAP_STYLE_FLAT;
        sp.endCap   = D2D1_CAP_STYLE_FLAT;
        cv->d2dFactory->CreateStrokeStyle(sp, NULL, 0, &cv->stroke);
    }

    /* DirectWrite */
    hr = DWriteCreateFactory(DWRITE_FACTORY_TYPE_SHARED, __uuidof(IDWriteFactory),
                             (IUnknown**)&cv->dwFactory);
    if (FAILED(hr)) { seterr(cv, "DWriteCreateFactory", hr); return cv; }

    hr = cv->dwFactory->CreateTextFormat(L"Consolas", NULL,
            DWRITE_FONT_WEIGHT_BOLD, DWRITE_FONT_STYLE_NORMAL, DWRITE_FONT_STRETCH_NORMAL,
            12.0f, L"en-us", &cv->txtFmt);
    if (FAILED(hr)) { seterr(cv, "CreateTextFormat", hr); return cv; }
    cv->txtFmt->SetTextAlignment(DWRITE_TEXT_ALIGNMENT_LEADING);
    cv->txtFmt->SetParagraphAlignment(DWRITE_PARAGRAPH_ALIGNMENT_NEAR);

    /* 抗锯齿：DComp 逐像素 alpha 下用 per-primitive */
    cv->d2dCtx->SetAntialiasMode(D2D1_ANTIALIAS_MODE_PER_PRIMITIVE);
    cv->d2dCtx->SetTextAntialiasMode(D2D1_TEXT_ANTIALIAS_MODE_GRAYSCALE);

    {
        RECT rc;
        GetClientRect(hwnd, &rc);
        if (!build_size(cv, (UINT)(rc.right - rc.left), (UINT)(rc.bottom - rc.top)))
            return cv;
    }
    return cv;
}

void CV_Destroy(CV* cv)
{
    if (!cv) return;
    destroy_size(cv);
    if (cv->stroke)     cv->stroke->Release();
    if (cv->brush)      cv->brush->Release();
    if (cv->txtFmt)     cv->txtFmt->Release();
    if (cv->dwFactory)  cv->dwFactory->Release();
    if (cv->dcomp)      cv->dcomp->Release();
    if (cv->d2dCtx)     cv->d2dCtx->Release();
    if (cv->d2dDevice)  cv->d2dDevice->Release();
    if (cv->d2dFactory) cv->d2dFactory->Release();
    if (cv->ctx)        cv->ctx->Release();
    if (cv->dev)        cv->dev->Release();
    HeapFree(GetProcessHeap(), 0, cv);
}

const char* CV_Error(CV* cv) { return (cv && cv->err[0]) ? cv->err : NULL; }

BOOL CV_Begin(CV* cv)
{
    RECT rc;
    UINT w, h;
    if (!cv || !cv->swap) {
        if (!cv) return FALSE;
        GetClientRect(cv->hwnd, &rc);
        w = (UINT)(rc.right - rc.left);
        h = (UINT)(rc.bottom - rc.top);
        if (!build_size(cv, w, h)) return FALSE;
    }
    GetClientRect(cv->hwnd, &rc);
    w = (UINT)(rc.right - rc.left);
    h = (UINT)(rc.bottom - rc.top);
    if (w == 0 || h == 0) return FALSE;
    if (w != cv->width || h != cv->height) {
        if (!build_size(cv, w, h)) return FALSE;
    }
    cv->d2dCtx->BeginDraw();
    cv->d2dCtx->SetTransform(D2D1::Matrix3x2F::Identity());
    cv->d2dCtx->Clear(D2D1::ColorF(0, 0, 0, 0));   /* 全透明 */
    return TRUE;
}

void CV_End(CV* cv)
{
    HRESULT hr;
    if (!cv || !cv->swap) return;
    hr = cv->d2dCtx->EndDraw();
    if (FAILED(hr)) { seterr(cv, "EndDraw", hr); return; }
    /* 不等垂直同步：DWM 会按自己的节拍合成我们的视觉，
       等 vsync 反而会和 16ms 定时器叠加成 ~40fps */
    hr = cv->swap->Present(0, 0);
    if (FAILED(hr)) seterr(cv, "Present", hr);
}

static ID2D1SolidColorBrush* col(CV* cv, float r, float g, float b, float a)
{
    cv->brush->SetColor(D2D1::ColorF(r, g, b, a));
    return cv->brush;
}

void CV_Rect(CV* cv, float l, float t, float r, float b,
             float cr, float cg, float cb, float width)
{
    if (!cv || !cv->d2dCtx) return;
    cv->d2dCtx->DrawRectangle(D2D1::RectF(l, t, r, b), col(cv, cr, cg, cb, 1.0f),
                              width, cv->stroke);
}

void CV_FillRect(CV* cv, float l, float t, float r, float b,
                 float cr, float cg, float cb)
{
    if (!cv || !cv->d2dCtx) return;
    cv->d2dCtx->FillRectangle(D2D1::RectF(l, t, r, b), col(cv, cr, cg, cb, 1.0f));
}

void CV_Line(CV* cv, float x0, float y0, float x1, float y1,
             float cr, float cg, float cb, float width)
{
    if (!cv || !cv->d2dCtx) return;
    cv->d2dCtx->DrawLine(D2D1::Point2F(x0, y0), D2D1::Point2F(x1, y1),
                         col(cv, cr, cg, cb, 1.0f), width, cv->stroke);
}

void CV_Circle(CV* cv, float x, float y, float rad,
               float cr, float cg, float cb, float width)
{
    if (!cv || !cv->d2dCtx) return;
    cv->d2dCtx->DrawEllipse(D2D1::Ellipse(D2D1::Point2F(x, y), rad, rad),
                            col(cv, cr, cg, cb, 1.0f), width, cv->stroke);
}

void CV_Text(CV* cv, float x, float y, const char* s, int len,
             float cr, float cg, float cb)
{
    D2D1_RECT_F rc;
    WCHAR* wbuf;
    int wn, i;
    if (!cv || !cv->d2dCtx || !cv->dwFactory || !s || len <= 0) return;
    if (len > 500) len = 500;

    wbuf = (WCHAR*)HeapAlloc(GetProcessHeap(), 0, (len + 1) * sizeof(WCHAR));
    if (!wbuf) return;
    wn = MultiByteToWideChar(CP_ACP, 0, s, len, wbuf, len);
    if (wn <= 0) { HeapFree(GetProcessHeap(), 0, wbuf); return; }
    wbuf[wn] = 0;

    rc.left = x; rc.top = y; rc.right = x + 900; rc.bottom = y + 60;
    cv->d2dCtx->DrawText(wbuf, (UINT32)wn, cv->txtFmt, rc,
                         col(cv, cr, cg, cb, 1.0f),
                         D2D1_DRAW_TEXT_OPTIONS_NONE,
                         DWRITE_MEASURING_MODE_NATURAL);
    (void)i;
    HeapFree(GetProcessHeap(), 0, wbuf);
}
