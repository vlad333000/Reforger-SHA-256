// Enable debugging
// #define SHA256_DEBUG

// Enable debug memory allocations
// #define SHA256_DEBUG_ALLOC

// Force chunk to zero on init and resetting (Normally it shouldn't required)
// #define SHA256_ZERO_CHUNK

// Verbose level
// #define SHA256_DEBUG_V
// #define SHA256_DEBUG_V_V
// #define SHA256_DEBUG_V_V_V
// #define SHA256_DEBUG_V_V_V_V

class SHA256 {
	static const int s_HashSize = 256;

    static const int s_WordSize = SHA256_Helper.s_IntSizeBits;

	static const int s_WordsCount = s_HashSize / s_WordSize;

    protected int m_Words[s_WordsCount];

    void SHA256(int words[s_WordsCount]) {
        #ifdef SHA256_DEBUG_ALLOC
        PrintFormat("[SHA256] %1: Created!", this);
		PrintFormat("[SHA256]   hash_size = %1", s_HashSize);
		PrintFormat("[SHA256]   word_size = %1", s_WordSize);
		PrintFormat("[SHA256]   words_count = %1", s_WordsCount);
        #endif

		for (int i = 0; i < s_WordsCount; i++)
			m_Words[i] = words[i];

        #ifdef SHA256_DEBUG_V
        PrintFormat("[SHA256]   words = %1", words);
		for (int i = 0; i < s_WordsCount; i++)
            PrintFormat("[SHA256]     words[%1] = 0x%2", i, SHA256_Helper.IntToStringHex(words[i]));
        #endif
    };

    void ~SHA256() {
        #ifdef SHA256_DEBUG_ALLOC
        PrintFormat("[SHA256] %1: Deleted!", this);
        #endif
    };

	static SHA256 Hash(string data) {
		SHA256_Stream stream();
		stream.Push(data);
		return stream.Hash();
	};

	static SHA256 Hash(notnull array<int> bytes) {
		SHA256_Stream stream();
		stream.PushBytes(bytes);
		return stream.Hash();
	};

	static SHA256 Hash(notnull array<int> bytes, int nbits) {
		SHA256_Stream stream();
		stream.PushBytesV(bytes, nbits);
		return stream.Hash();
	};

    SHA256 Copy() {
        return new SHA256(m_Words);
    };

    bool IsEqualTo(notnull SHA256 other) {
        for (int i = 0; i < s_WordsCount; i++)
            if (m_Words[i] != other.m_Words[i])
                return false;
        return true;
    };

    string AsString() {
        auto result = "";
        for (int i = 0; i < s_WordsCount; i++)
            result += SHA256_Helper.IntToStringHex(m_Words[i]);
        return result;
    };



	static bool Extract(SHA256 instance, ScriptCtx ctx, SSnapSerializerBase snapshot) {
        for (int i = 0; i < s_WordsCount; i++) {
            int word = instance.m_Words[i];
            snapshot.SerializeInt(word);
        };
		return true;
	};

	static bool Inject(SSnapSerializerBase snapshot, ScriptCtx ctx, SHA256 instance) {
        for (int i = 0; i < s_WordsCount; i++) {
            int word;
            snapshot.SerializeInt(word);
            instance.m_Words[i] = word;
        };
		return true;
	};

	static void Encode(SSnapSerializerBase snapshot, ScriptCtx ctx, ScriptBitSerializer packet) {
        for (int i = 0; i < s_WordsCount; i++)
		    snapshot.EncodeInt(packet);
	};

	static bool Decode(ScriptBitSerializer packet, ScriptCtx ctx, SSnapSerializerBase snapshot) {
        for (int i = 0; i < s_WordsCount; i++)
		    snapshot.DecodeInt(packet);
		return true;
	};

	static bool SnapCompare(SSnapSerializerBase lhs, SSnapSerializerBase rhs, ScriptCtx ctx) {
        for (int i = 0; i < s_WordsCount; i++) {
            int lword;
            lhs.SerializeInt(lword);
            int rword;
            rhs.SerializeInt(rword);
            if (lword != rword)
                return false;
        };
		return true;
	};

	static bool PropCompare(SHA256 instance, SSnapSerializerBase snapshot, ScriptCtx ctx) {
        for (int i = 0; i < s_WordsCount; i++)
		    if (!snapshot.CompareInt(instance.m_Words[i]))
                return false;
		return true;
	};

	static bool FromSnapshot(SSnapSerializerBase snapshot, ScriptCtx ctx, out SHA256 instance) {
		int words[s_WordsCount];
		for (int i = 0; i < s_WordsCount; i++) {
			int word;
			snapshot.SerializeInt(word);
			words[i] = word;
		};
		instance = new SHA256(words);
		return true;
	};
};

class SHA256_Stream {
    protected static const int s_HCount = SHA256.s_WordsCount;

    protected int m_H[s_HCount];

    protected static const int s_HInit[s_HCount] = {
        0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19
    };

    protected static const int s_KCount = 64;

    protected static const int s_K[s_KCount] = {
        0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
        0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
        0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
        0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
        0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
        0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
        0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
        0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2
    };

    protected int m_L;

    static const int s_ChunkSize = 512;

    static const int s_ChunkWordSize = SHA256_Helper.s_IntSizeBits;

    static const int s_ChunkWordsCount = s_ChunkSize / s_ChunkWordSize;

    protected int m_Chunk[s_ChunkWordsCount];



    void SHA256_Stream() {
        #ifdef SHA256_DEBUG_ALLOC
        PrintFormat("[SHA256] %1: Created!", this);

        PrintFormat("[SHA256]   h_count = %1", s_HCount);
        PrintFormat("[SHA256]   h_init = %1", s_HInit);
        foreach (auto i, auto v : s_HInit)
        PrintFormat("[SHA256]     h_init[%1] = 0x%2", i, SHA256_Helper.IntToStringHex(v));

        PrintFormat("[SHA256]   k_count = %1", s_KCount);
        PrintFormat("[SHA256]   k = %1", s_K);
        foreach (auto i, auto v : s_K)
        PrintFormat("[SHA256]     k[%1] = 0x%2", i, SHA256_Helper.IntToStringHex(v));

        PrintFormat("[SHA256]   chunk_size = %1", s_ChunkSize);
        PrintFormat("[SHA256]   chunk_word_size = %1", s_ChunkWordSize);
        PrintFormat("[SHA256]   chunk_words_count = %1", s_ChunkWordsCount);
        #endif

        Reset();
    };

    void ~SHA256_Stream() {
        #ifdef SHA256_DEBUG_ALLOC
        PrintFormat("[SHA256] %1: Deleted!", this);
        #endif
    };



    // Push single bit `bit` (true is 1, false is 0)
    void PushBit(bool bit) {
        int i;
        if (bit)
            i = 1;
        else
            i = 0;
        PushBit(i);
    };

    // Push bit `bit` `n` time(s) (true is 1, false is 0)
    void PushBit(bool bit, int n) {
        for (int i = 0; i < n; i++)
            PushBit(bit);
    };

    // Push bits from array `bits`, where each value is a bit (true is 1, false is 0)
    void PushBits(notnull array<bool> bits) {
        foreach (auto bit : bits)
            PushBit(bit);
    };


    // Push bits, accept only 0 and 1 as input
    void PushBit(int bit) {
        int l = m_L % s_ChunkSize;
        int i = l / s_ChunkWordSize;
        int j = s_ChunkWordSize - (l % s_ChunkWordSize) - 1;
        m_Chunk[i] = (m_Chunk[i] & ~(1 << j)) | (bit << j);
        m_L++;
		if (m_L % s_ChunkSize == 0)
			ProcessChunk();
    };

    void PushBit(int bit, int n) {
        for (int i = 0; i < n; i++)
            PushBit(bit);
    };

    void PushBits(notnull array<int> bits) {
        foreach (auto bit : bits)
            PushBit(bit);
    };


    // Push bytes (8 bits)
    void PushByte(int byte) {
		PushBitsV(byte, 8);
	};

    void PushByte(int byte, int n) {
        for (int i = 0; i < n; i++)
            PushByte(byte);
    };

    void PushBytes(int bytes[], int n) {
        for (int i = 0; i < n; i++)
            PushByte(bytes[i]);
    };

    void PushBytes(notnull array<int> bytes) {
        foreach (auto byte : bytes)
            PushByte(byte);
    };

    // Push n bits from supplied data
    void PushBitsV(int bits, int n) {
		for (int i = 0; i < n; i++) {
			auto b = bits & (1 << (n - i - 1));
			PushBit(b != 0);
		};
	};

    void PushBitsV(int bits[], int n) {
        for (int i = 0; i < n / s_ChunkWordSize; i++)
            PushBitsV(bits[i], s_ChunkWordSize);
        PushBitsV(bits[n / s_ChunkWordSize], n % s_ChunkWordSize);
    };

    void PushBitsV(notnull array<int> bits, int n) {
        for (int i = 0; i < n / s_ChunkWordSize; i++)
            PushBitsV(bits[i], s_ChunkWordSize);
        PushBitsV(bits[n / s_ChunkWordSize], n % s_ChunkWordSize);
    };

	void PushBytesV(notnull array<int> bytes, int n) {
		for (int i = 0; i < n / 8; i++)
			PushByte(bytes[i]);
		PushBitsV(bytes[n / 8], n % 8);
	};


    // Push words (32 bits)
    void PushWord(int word) {
		PushBitsV(word, s_ChunkWordSize);
	};

    void PushWord(int word, int n) {
        for (int i = 0; i < n; i++)
            PushWord(word);
    };

    void PushWords(int words[], int n) {
        for (int i = 0; i < n; i++)
            PushWord(words[i]);
    };

    void PushWords(notnull array<int> words) {
        foreach (auto word : words)
            PushWord(word);
    };

    void PushChunk(int chunk[s_ChunkWordsCount]) {
        for (int i = 0; i < s_ChunkWordsCount; i++)
            PushWord(chunk[i]);
    };


    // Push data, according to https://community.bistudio.com/wiki/Arma_Reforger:Scripting:_Values#Primitive_Types
    void Push(int x) {
        PushWord(x);
    };

    void Push(float x) {
	    Debug.Error("Not implemented!");
    };

    void Push(bool x) {
        int i;
        if (x)
            i = 0x00000001;
        else
            i = 0x00000000;
        Push(i);
    };

    void Push(string x) {
        for (int i = 0; i < x.Length(); i++)
            PushByte(x.ToAscii(i));
    };

    void Push(vector x) {
        Push(x[0]);
        Push(x[1]);
        Push(x[2]);
    };

    SHA256 Hash() {
        #ifdef SHA256_DEBUG
        PrintFormat("[SHA256] %1: Hashing...", this);
        #endif

        Finalize();

        auto hash = new SHA256(m_H);

        #ifdef SHA256_DEBUG
        PrintFormat("[SHA256] %1: Hashed!", this);
        PrintFormat("[SHA256]   hash = %1 (0x%2)", hash, hash.AsString());
        #endif

        Reset();

        return hash;
    };

    SHA256 Hash(bool reset) {
        if (reset)
            return Hash();

        #ifdef SHA256_DEBUG
        PrintFormat("[SHA256] %1: Hashing...", this);
        #endif

        int L0 = m_L;
        int h0[s_HCount];
		for (int i = 0; i < s_HCount; i++)
            h0[i] = m_H[i];
        #ifdef SHA256_ZERO_CHUNK
        int chunk0[s_ChunkWordsCount]
        for (int i = 0; i < s_ChunkWordsCount; i++)
            chunk0[i] = m_Chunk[i];
        #endif

        #ifdef SHA256_DEBUG_V_V
        PrintFormat("[SHA256]   Saved state:");
		PrintFormat("[SHA256]     L0 = %1", L0);
		PrintFormat("[SHA256]     h0 = %1", h0);
		foreach (auto i, auto v : h0)
		 	PrintFormat("[SHA256]      h0[%1] = 0x%2", i, SHA256_Helper.IntToStringHex(v));
        #ifdef SHA256_ZERO_CHUNK
		PrintFormat("[SHA256]     chunk0 = %1", chunk0);
		foreach (auto i, auto v : chunk0)
		 	PrintFormat("[SHA256]      chunk0[%1] = 0x%2", i, SHA256_Helper.IntToStringHex(v));
        #endif
        #endif

        Finalize();

        auto hash = new SHA256(m_H);

        #ifdef SHA256_DEBUG
        PrintFormat("[SHA256] %1: Hashed!", this);
        PrintFormat("[SHA256]   hash = %1 (0x%2)", hash, hash.AsString());
        #endif

        m_L = L0;
		for (int i = 0; i < s_HCount; i++)
            m_H[i] = h0[i];
        #ifdef SHA256_ZERO_CHUNK
        for (int i = 0; i < s_ChunkWordsCount; i++)
            m_Chunk[i] = chunk0[i];
        #endif

        #ifdef SHA256_DEBUG_V_V
        PrintFormat("[SHA256]   Restored state:");
		PrintFormat("[SHA256]     L = %1", m_L);
		PrintFormat("[SHA256]     h = %1", m_H);
		foreach (auto i, auto v : h0)
		 	PrintFormat("[SHA256]      h[%1] = 0x%2", i, SHA256_Helper.IntToStringHex(v));
        #ifdef SHA256_ZERO_CHUNK
		PrintFormat("[SHA256]     chunk = %1", m_Chunk);
		foreach (auto i, auto v : m_Chunk)
		 	PrintFormat("[SHA256]      chunk[%1] = 0x%2", i, SHA256_Helper.IntToStringHex(v));
        #endif
        #endif

        return hash;
    };

    void Reset() {
        #ifdef SHA256_DEBUG
        PrintFormat("[SHA256] %1: Resetting...", this);
        #endif

		foreach (auto i, auto v : s_HInit)
			m_H[i] = v;

        #ifdef SHA256_DEBUG_V_V
		PrintFormat("[SHA256]   h = %1", m_H);
		foreach (auto i, auto v : m_H)
		 	PrintFormat("[SHA256]      h[%1] = 0x%2", i, SHA256_Helper.IntToStringHex(v));
        #endif

		m_L = 0;

        #ifdef SHA256_DEBUG_V_V
		PrintFormat("[SHA256]   L = %1", m_L);
        #endif

        #ifdef SHA256_ZERO_CHUNK
		foreach (auto i, auto v : m_Chunk)
            chunk[i] = 0x00000000;

        #ifdef SHA256_DEBUG_V_V
		PrintFormat("[SHA256]   chunk = %1", m_Chunk);
        foreach (auto i, auto v : m_Chunk)
            PrintFormat("[SHA256]     chunk[%1] = 0x%2", i, SHA256_Helper.IntToStringHex(v));
        #endif
        #endif

        #ifdef SHA256_DEBUG
        PrintFormat("[SHA256] %1: Resetted!", this);
        #endif
    };



    protected void Finalize() {
        #ifdef SHA256_DEBUG_V
        PrintFormat("[SHA256]   Finalizing...");
        #endif

        auto K = 0;
		while ((m_L + 1 + K + 64) % s_ChunkSize != 0)
			K++;

        #ifdef SHA256_DEBUG_V_V
        PrintFormat("[SHA256]     L = %1", m_L);
        PrintFormat("[SHA256]     K = %1", K);
        #endif

		auto l = m_L;
        PushBit(1);
        for (int i = 0; i < K; i++)
            PushBit(0);
        PushWord(0);
        PushWord(l);

        #ifdef SHA256_DEBUG_V
        PrintFormat("[SHA256]   Finalized!");
        #endif
    };

    protected void ProcessChunk() {
		#ifdef SHA256_DEBUG
		auto n = m_L / s_ChunkSize - 1;
		PrintFormat("[SHA256]   %1: Processing chunk #%2...", this, n);
        #endif

        #ifdef SHA256_DEBUG_V_V
        PrintFormat("[SHA256]     chunk = %1", m_Chunk);
		foreach (auto i, auto v : m_Chunk)
			PrintFormat("[SHA256]       chunk[%1] = 0x%2", i, SHA256_Helper.IntToStringHex(v));
		#endif

        #ifdef SHA256_DEBUG_V_V_V_V
        PrintFormat("[SHA256]     Scheduling...");
        #endif

        int w[s_KCount];

        for (int i = 0; i < s_ChunkWordsCount; i++) {
            w[i] = m_Chunk[i];
            #ifdef SHA256_DEBUG_V_V_V_V
		    PrintFormat("[SHA256]       i = %1", i);
		    PrintFormat("[SHA256]         w[i] = 0x%1", SHA256_Helper.IntToStringHex(w[i]));
            #endif
        };

        for (int i = s_ChunkWordsCount; i < s_KCount; i++) {
            int s0 = SHA256_Helper.rotr(w[i - 15], 7) ^ SHA256_Helper.rotr(w[i - 15], 18) ^ SHA256_Helper.shr(w[i - 15], 3);
            int s1 = SHA256_Helper.rotr(w[i - 2], 17) ^ SHA256_Helper.rotr(w[i - 2], 19) ^ SHA256_Helper.shr(w[i - 2], 10);
            w[i] = w[i - 16] + s0 + w[i - 7] + s1;
            #ifdef SHA256_DEBUG_V_V_V_V
		    PrintFormat("[SHA256]       i = %1", i);
		    PrintFormat("[SHA256]         s0 = 0x%1", SHA256_Helper.IntToStringHex(s0));
		    PrintFormat("[SHA256]         s1 = 0x%1", SHA256_Helper.IntToStringHex(s1));
		    PrintFormat("[SHA256]         w[i - 15] = 0x%1", SHA256_Helper.IntToStringHex(w[i - 15]));
		    PrintFormat("[SHA256]         w[i - 2] = 0x%1", SHA256_Helper.IntToStringHex(w[i - 2]));
		    PrintFormat("[SHA256]         w[i - 16] = 0x%1", SHA256_Helper.IntToStringHex(w[i - 16]));
		    PrintFormat("[SHA256]         w[i - 7] = 0x%1", SHA256_Helper.IntToStringHex(w[i - 7]));
		    PrintFormat("[SHA256]         w[i] = 0x%1", SHA256_Helper.IntToStringHex(w[i]));
            #endif
        };

        #ifdef SHA256_DEBUG_V_V_V_V
        PrintFormat("[SHA256]     Scheduled!");
        #endif

		#ifdef SHA256_DEBUG_V_V_V
		PrintFormat("[SHA256]     w = %1", w);
		foreach (auto i, auto v : w)
			PrintFormat("[SHA256]       w[%1] = 0x%2", i, SHA256_Helper.IntToStringHex(v));
		#endif

        int v[s_HCount];
        for (int i = 0; i < s_HCount; i++)
            v[i] = m_H[i];

		#ifdef SHA256_DEBUG_V_V_V
        PrintFormat("[SHA256]   Compression...");
		PrintFormat("[SHA256]     v = %1", v);
		foreach (auto i, auto x : v)
			PrintFormat("[SHA256]       v[%1] = 0x%2", i, SHA256_Helper.IntToStringHex(x));
		#endif

        for (int i = 0; i < s_KCount; i++) {
            int S1 = SHA256_Helper.rotr(v[4], 6) ^ SHA256_Helper.rotr(v[4], 11) ^ SHA256_Helper.rotr(v[4], 25);
            int ch = (v[4] & v[5]) ^ ((~v[4]) & v[6]);
            int temp1 = v[7] + S1 + ch + s_K[i] + w[i];
            int S0 = SHA256_Helper.rotr(v[0], 2) ^ SHA256_Helper.rotr(v[0], 13) ^ SHA256_Helper.rotr(v[0], 22);
            int maj = (v[0] & v[1]) ^ (v[0] & v[2]) ^ (v[1] & v[2]);
            int temp2 = S0 + maj;

            #ifdef SHA256_DEBUG_V_V_V_V
		    PrintFormat("[SHA256]       i = %1", i);
		    PrintFormat("[SHA256]         calc");
		    PrintFormat("[SHA256]           v[4] = 0x%1", SHA256_Helper.IntToStringHex(v[4]));
		    PrintFormat("[SHA256]           S1 = 0x%1", SHA256_Helper.IntToStringHex(S1));
		    PrintFormat("[SHA256]           v[5] = 0x%1", SHA256_Helper.IntToStringHex(v[5]));
		    PrintFormat("[SHA256]           v[6] = 0x%1", SHA256_Helper.IntToStringHex(v[6]));
		    PrintFormat("[SHA256]           ch = 0x%1", SHA256_Helper.IntToStringHex(ch));
		    PrintFormat("[SHA256]           v[7] = 0x%1", SHA256_Helper.IntToStringHex(v[7]));
		    PrintFormat("[SHA256]           k[i] = 0x%1", SHA256_Helper.IntToStringHex(s_K[i]));
		    PrintFormat("[SHA256]           w[i] = 0x%1", SHA256_Helper.IntToStringHex(w[i]));
		    PrintFormat("[SHA256]           temp1 = 0x%1", SHA256_Helper.IntToStringHex(temp1));
		    PrintFormat("[SHA256]           v[0] = 0x%1", SHA256_Helper.IntToStringHex(v[0]));
		    PrintFormat("[SHA256]           S0 = 0x%1", SHA256_Helper.IntToStringHex(S0));
		    PrintFormat("[SHA256]           v[1] = 0x%1", SHA256_Helper.IntToStringHex(v[1]));
		    PrintFormat("[SHA256]           v[2] = 0x%1", SHA256_Helper.IntToStringHex(v[2]));
		    PrintFormat("[SHA256]           maj = 0x%1", SHA256_Helper.IntToStringHex(maj));
		    PrintFormat("[SHA256]           temp2 = 0x%1", SHA256_Helper.IntToStringHex(temp2));
		    PrintFormat("[SHA256]           v[3] = 0x%1", SHA256_Helper.IntToStringHex(v[3]));
            #endif

            v[7] = v[6];
            v[6] = v[5];
            v[5] = v[4];
            v[4] = v[3] + temp1;
            v[3] = v[2];
            v[2] = v[1];
            v[1] = v[0];
            v[0] = temp1 + temp2;

            #ifdef SHA256_DEBUG_V_V_V_V
		    PrintFormat("[SHA256]         compress");
		    PrintFormat("[SHA256]           v = %1", v);
		    foreach (auto j, auto x : v)
			    PrintFormat("[SHA256]             v[%1] = 0x%2", j, SHA256_Helper.IntToStringHex(x));
            #endif
        };

		#ifdef SHA256_DEBUG_V_V_V
        PrintFormat("[SHA256]   Compressed!");
		PrintFormat("[SHA256]     v = %1", v);
		foreach (auto i, auto x : v)
			PrintFormat("[SHA256]       v[%1] = 0x%2", i, SHA256_Helper.IntToStringHex(x));
		#endif

        for (int i = 0; i < 8; i++)
            m_H[i] = m_H[i] + v[i];

		#ifdef SHA256_DEBUG_V_V_V
		PrintFormat("[SHA256]     h = %1", m_H);
		foreach (auto i, auto x : m_H)
			PrintFormat("[SHA256]       h[%1] = 0x%2", i, SHA256_Helper.IntToStringHex(x));
		#endif

		#ifdef SHA256_DEBUG
		PrintFormat("[SHA256]   Chunk process completed!", n);
		#endif
    };
};

class SHA256_Helper {
    static const int s_ByteSize = 8;

    static const int s_ByteMask = 0xFF;

    static const int s_ByteHalfSize = 4;

    static const int s_ByteHalfMask = 0x0F;

    static const int s_IntSize = 4;

    static const int s_IntSizeBits = s_IntSize * s_ByteSize;

    static const int s_IntSignMask = 0x80000000;

    static const string s_Hex = "0123456789abcdef";

	// rotate right
	static int rotr(int x, int n) {
	    return shr(x, n) | (x << (s_IntSizeBits - n));
	};

	// shift right logical
	static int shr(int x, int n) {
	    if (x < 0)
			return ((x & ~s_IntSignMask) >> n) | (1 << (s_IntSizeBits - n - 1));
	    return x >> n;
	};

	static string IntToStringHex(int x) {
		auto result = "";
	    for (int i = 0; i < s_IntSize; i++) {
	        auto byte = (x >> ((s_IntSize - i - 1) * s_ByteSize)) & s_ByteMask;
	        result += s_Hex[byte >> s_ByteHalfSize];
	        result += s_Hex[byte & s_ByteHalfMask];
	    };
		return result;
	};
};
