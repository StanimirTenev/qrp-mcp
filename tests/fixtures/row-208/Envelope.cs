using Amazon.KeyManagementService;
using Amazon.KeyManagementService.Model;
using System.Security.Cryptography;

public class Envelope
{
    private readonly AmazonKeyManagementServiceClient _kms = new AmazonKeyManagementServiceClient();

    // partner key establishment: new ML-KEM key in KMS
    public async Task<string> CreatePartnerKey() {
        var r = await _kms.CreateKeyAsync(new CreateKeyRequest {
            KeySpec = KeySpec.ML_KEM_768,
            KeyUsage = KeyUsageType.ENCAPSULATE_DECAPSULATE });
        return r.KeyMetadata.KeyId;
    }

    public byte[] DeriveKey(byte[] sharedSecret) {
        return HKDF.DeriveKey(HashAlgorithmName.SHA256, sharedSecret, 32);
    }

    // stored records: unchanged envelope encryption under an RSA KMS key
    public async Task<byte[]> WrapRecordKey(string keyId, byte[] dataKey) {
        var r = await _kms.EncryptAsync(new EncryptRequest {
            KeyId = keyId, Plaintext = new MemoryStream(dataKey),
            EncryptionAlgorithm = EncryptionAlgorithmSpec.RSAES_OAEP_SHA_256 });
        return r.CiphertextBlob.ToArray();
    }

    // archive signing: unchanged
    public async Task<string> CreateSigningKey() {
        var r = await _kms.CreateKeyAsync(new CreateKeyRequest {
            KeySpec = KeySpec.RSA_2048, KeyUsage = KeyUsageType.SIGN_VERIFY });
        return r.KeyMetadata.KeyId;
    }

    public byte[] EncryptLocal(byte[] key, byte[] data) {
        using var aes = Aes.Create(); aes.Key = key; aes.Mode = CipherMode.CBC;
        return aes.CreateEncryptor().TransformFinalBlock(data, 0, data.Length);
    }
}
