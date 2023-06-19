#include <Windows.h>
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
auto main() -> int {
    printf("acpi sandbox detect by huoji 2023.6.19 \n");

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
        bool foundHpet = false;
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

            // printf("tid: %s oemid: %s oem_table_id: %llX oem_table_xd: %llX
            // \n",
            //        tid, oemid, tableHeader->oem_table_id,
            //        (tableHeader->oem_table_id & 0xFFFFFFFF));
            if (memcmp(oemid, "WAET", 4) == 0) {
                printf(
                    "[detected] Vmware detected by Windows ACPI Emulated"
                    "\n");
            }
            if (foundHpet == false && memcmp(oemid, "HPET", 4) == 0) {
                foundHpet = true;
            }
            if ((tableHeader->oem_table_id & 0xFFFFFFFF) == 0) {
                printf(
                    "[detected] Cuckoo sandbox detected by oem table id"
                    "\n");
            }
            index++;
        }
        if (index < 8) {
            printf("[detected] vm-guest detected by table size \n");
        }
        if (foundHpet == false) {
            printf("[detected] HPET not found,Cuckoo detected \n");
        }

    } while (false);
    if (firmwareTableBuffer != nullptr) {
        free(firmwareTableBuffer);
    }
    getchar();
    return 0;
}
