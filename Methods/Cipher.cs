/// <summary>
/// Simple XOR cipher
/// </summary>
/// <param name="data"></param>
/// <param name="key"></param>
public static void Cipher(byte[] data, byte[] key)
{
    for (int i = 0; i < data.Length; i++)
    {
        data[i] ^= key[i % key.Length];
    }
}