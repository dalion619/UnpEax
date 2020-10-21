
struct EAPPX_HEADER 

	DWORD Magic; // "EXPH"/"EXSH"/"EXBH"
	WORD HeaderSize;
	QWORD Version;
	QWORD FooterOffset;
	QWORD FooterLength;
	QWORD FileCount;
	QWORD SignatureOffset;
	WORD SignatureCompressionType;
	DWORD SignatureUncompressedLength;
	DWORD SignatureLength;
	QWORD CodeIntegrityOffset;
	WORD CodeIntegrityCompressionType;
	DWORD CodeIntegrityUncompressedLength;
	DWORD CodeIntegrityLength;
	QWORD BlockMapFileID;
	DWORD KeyLength;
	WORD KeyIDCount;
	EAPPX_KEYID KeyIDs[KeyIDCount];
	WORD PackageFullNameStrLen;
	WORD PackageFullNameByteLen;
	WCHAR PackageFullName[PackageFullNameStrLen];
	WORD CryptoAlgoLength;
	WCHAR CryptoAlgo[CryptoAlgoLength/2];
	WORD DiffusionSupportEnabled;
	WORD BlockMapHashAlgoLength;
	WCHAR BlockMapHashAlgo[BlockMapHashAlgoLength/2];
	WORD BlockMapHashLength;
	CHAR BlockMapHash[BlockMapHashLength];    


struct EAPPX_KEYID 

	GUID KeyParts[2];



struct EAPPX_FOOTER 

	WORD Magic; // "EF" (EAppx Footer?)
	WORD FooterSize; // must be at least 0x28 bytes
	WORD KeyIDIndex; // if 0xffff, not encrypted?
	WORD CompressionType; // 0: not compressed. 1: raw DEFLATE.
	QWORD FileID;
	QWORD OffsetToFile;
	QWORD UncompressedLength;
	QWORD CompressedLength;


If KeyParts[0] == {BB1755DB-5052-4B10-B2AB-F3ABF5CA5B41}

KeyID is 16 bytes long and is KeyParts[1]
 else, KeyID is 32 bytes long, the entirety of KeyParts

"EXPH" magic allows empty (ie, 0) CodeIntegrity fields
the others must have them filled.

"EXPH" magic must have footers / "appendOffset" (??)

"EXBH" magic must have signature included.

Package name cannot be over 127 bytes. There can not be over 0x100 key IDs.

"EXSH" magic does no real checks on if the signature offset/size/etc is valid.

EXBH => eappxbundle, EXPH => eappx. EXSH => maybe unsigned eappx?

eappxbundles contain the various raw eappxes.