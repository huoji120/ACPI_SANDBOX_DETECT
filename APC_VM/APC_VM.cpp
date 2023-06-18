﻿#include <Windows.h>
#include <stdio.h>
#include <cstdint>
#include <iostream>
struct acpi_table_header {
    uint32_t signature;
    uint32_t length;
    uint8_t revision;
    uint8_t checksum;
    char oem_id[6];
    uint64_t oem_table_id;
    uint32_t oem_revision;
    uint32_t creator_id;
    uint32_t creator_revision;
};
struct hpet_acpi_data {
    uint32_t hardware_block_id;
    uint8_t space_id;
    uint8_t bit_width;
    uint8_t bit_offset;
    uint8_t encoded_access_width;
    uint64_t address;
    uint8_t sequence_number;
    uint16_t minimum_clock_ticks;
    uint8_t flags;
};
static const auto FirmwareTableProviderSignature = 'ACPI';

auto getHPETData() -> std::pair<bool, std::shared_ptr<hpet_acpi_data>> {
    static const auto HPETSignature = 'TEPH';
    const auto tableBufferSize = GetSystemFirmwareTable(
        FirmwareTableProviderSignature, HPETSignature, NULL, NULL);
    hpet_acpi_data hpetData;
    bool isSuccess = false;
    if (tableBufferSize == 0) {
        return {isSuccess, nullptr};
    }
    const auto tableBuffer = reinterpret_cast<char*>(malloc(tableBufferSize));
    do {
        if (tableBuffer == nullptr) {
            break;
        }
        if (GetSystemFirmwareTable(FirmwareTableProviderSignature,
                                   HPETSignature, tableBuffer,
                                   tableBufferSize) == 0) {
            break;
        }
        const auto bodyAddress =
            reinterpret_cast<char*>(reinterpret_cast<uint64_t>(tableBuffer) +
                                    sizeof(acpi_table_header));
        memcpy(&hpetData, bodyAddress, sizeof(hpet_acpi_data));
        isSuccess = true;
    } while (false);
    if (tableBuffer) {
        free(tableBuffer);
    }
    return {isSuccess, std::make_shared<hpet_acpi_data>(hpetData)};
}
auto main() -> int {
    printf("acpi sandbox detect by huoji 2023.6.19 \n");
    /*
    auto firmwareTableBufferSize =
        EnumSystemFirmwareTables(FirmwareTableProviderSignature, 0, 0);
    char* firmwareTableBuffer = nullptr;
    do {
        if (firmwareTableBufferSize == 0) {
            break;
        }
        firmwareTableBuffer =
            reinterpret_cast<char*>(malloc(firmwareTableBufferSize));
        if (firmwareTableBuffer == nullptr) {
            break;
        }
        firmwareTableBufferSize = EnumSystemFirmwareTables(
            FirmwareTableProviderSignature, firmwareTableBuffer,
            firmwareTableBufferSize);
        if (firmwareTableBufferSize == 0) {
            break;
        }
        auto index = 0;
        for (size_t i = 0; i < firmwareTableBufferSize / 4; i++) {
            const auto tableHeader = reinterpret_cast<acpi_table_header*>(
                reinterpret_cast<uint64_t>(firmwareTableBuffer) + i);
            const auto tableID = *firmwareTableBuffer;
            char tid[6] = {0};
            char oemid[7] = {0};
            memcpy(tid, &tableHeader->signature, sizeof(unsigned long));
            memcpy(oemid, reinterpret_cast<char*>(tableHeader->oem_id),
                   sizeof(tableHeader->oem_id));

            printf("tid: %s oemid: %s oem_table_id: %08X \n", tid, oemid,
                   tableHeader->oem_table_id);
            if (memcmp(oemid, "WAET", 4) == 0) {
                printf(
                    "[detected] Vmware detected by Windows ACPI Emulated"
                    "\n");
            }
            if (tableHeader->oem_table_id == 0) {
                printf(
                    "[detected] Cuckoo sandbox detected by oem table id"
                    "\n");
            }
            index++;
        }
        if (index < 7) {
            printf("[detected] table size detected \n");
        }

    } while (false);
    if (firmwareTableBuffer != nullptr) {
        free(firmwareTableBuffer);
    }
    */
    auto [isSuccess, data] = getHPETData();
    if (isSuccess) {
        __debugbreak();
    }
    getchar();
    return 0;
}
