using System;
using System.Text;
using System.Runtime.InteropServices;

/// <summary>
/// Provides an unsafe method for reading PE section raw data. 
/// Useful for reading embedded configuration data from a PE section.
/// </summary>
public static unsafe class Section
{
    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern void* GetModuleHandleA(char* lpModuleName);

    /// <summary>
    /// Read section raw data
    /// </summary>
    /// <param name="sectionName">Section name</param>
    /// <returns>Section raw data or null</returns>
    public static byte[] Read(string sectionName)
    {
        // Get pointer to image base
        byte* pImageBase = (byte*)GetModuleHandleA(null);

        // Get pointer to offset to PE header
        byte* pPEHeaderOffset = pImageBase + PTR_PE_HEADER_OFFSET;

        // Get pointer to PE header
        byte* pPEHeader = pImageBase + *(int*)pPEHeaderOffset;

        // Get pointer to number of RVAs and sizes
        byte* pNumRVASizes = pPEHeader + NUM_RVA_SIZES_OFFSET;

        // Read number of PE sections
        int numPESections = *(short*)(pPEHeader + NUM_PE_SECTIONS_OFFSET);

        // Read number of RVAs and sizes
        int numRVAAndSizes = *(int*)pNumRVASizes;

        // Get pointer to first section header
        byte* pFirstSectionHeader = pNumRVASizes + (sizeof(int) + (numRVAAndSizes * (sizeof(int) * 2)));

        // Read section headers
        byte* pSectionHeader = pFirstSectionHeader;

        for (int i = 0; i < numPESections; i++)
        {
            // Read section header
            var _sectionName = Encoding.UTF8.GetString(pSectionHeader, SECTION_NAME_SIZE).TrimEnd('\0');

            if (_sectionName == sectionName)
            {
                int virtualAddress = *(int*)(pSectionHeader + SECTION_VIRTUAL_ADDRESS_OFFSET);
                int sizeRawData = *(int*)(pSectionHeader + SECTION_SIZE_RAW_DATA_OFFSET);

                // Copy section raw data to managed byte array
                var rawData = new byte[sizeRawData];
                byte* pRawData = pImageBase + virtualAddress;

                for (int j = 0; j < rawData.Length; j++)
                {
                    rawData[j] = *(pRawData + j);
                }

                return rawData;
            }

            // Move to next section header
            pSectionHeader = pSectionHeader + SECTION_HEADER_SIZE;
        }

        return null;
    }

    private const int PTR_PE_HEADER_OFFSET = 0x3C;
#if X64
    private const int NUM_RVA_SIZES_OFFSET = 0x84;
#else
    private const int NUM_RVA_SIZES_OFFSET = 0x74;
#endif
    private const int NUM_PE_SECTIONS_OFFSET = 0x6;
    private const int SECTION_HEADER_SIZE = 0x28;
    private const int SECTION_NAME_SIZE = 0x8;
    private const int SECTION_VIRTUAL_ADDRESS_OFFSET = 0xC;
    private const int SECTION_SIZE_RAW_DATA_OFFSET = 0x10;
}