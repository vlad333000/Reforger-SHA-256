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
	static const int hash_size = 256;

    static const int word_size = SHA256_Helper.int_size_bits;

	static const int words_count = hash_size / word_size;

    protected int words[words_count];

    void SHA256(int words[words_count]) {
        #ifdef SHA256_DEBUG_ALLOC
        PrintFormat("[SHA256] %1: Created!", this);
		PrintFormat("[SHA256]   hash_size = %1", hash_size);
		PrintFormat("[SHA256]   word_size = %1", word_size);
		PrintFormat("[SHA256]   words_count = %1", words_count);
        #endif

		for (int i = 0; i < words_count; i++)
			this.words[i] = words[i];

        #ifdef SHA256_DEBUG_V
        PrintFormat("[SHA256]   words = %1", words);
		for (int i = 0; i < words_count; i++)
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
        return new SHA256(this.words);
    };

    bool IsEqualTo(notnull SHA256 other) {
        for (int i = 0; i < words_count; i++)
            if (words[i] != other.words[i])
                return false;
        return true;
    };

    string AsString() {
        auto result = "";
        for (int i = 0; i < words_count; i++)
            result += SHA256_Helper.IntToStringHex(this.words[i]);
        return result;
    };
};

class SHA256_Stream {
    protected static const int h_count = SHA256.words_count;

    protected int h[h_count];

    protected static const int h_init[h_count] = {
        0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19
    };

    protected static const int k_count = 64;

    protected static const int k[k_count] = {
        0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
        0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
        0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
        0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
        0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
        0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
        0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
        0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2
    };

    protected int L;

    static const int chunk_size = 512;

    static const int chunk_word_size = SHA256_Helper.int_size_bits;

    static const int chunk_words_count = chunk_size / chunk_word_size;

    protected int chunk[chunk_words_count];



    void SHA256_Stream() {
        #ifdef SHA256_DEBUG_ALLOC
        PrintFormat("[SHA256] %1: Created!", this);
		
        PrintFormat("[SHA256]   h_count = %1", h_count);
        PrintFormat("[SHA256]   h_init = %1", h_init);
        foreach (auto i, auto v : h_init)
        PrintFormat("[SHA256]     h_init[%1] = 0x%2", i, SHA256_Helper.IntToStringHex(v));

        PrintFormat("[SHA256]   k_count = %1", k_count);
        PrintFormat("[SHA256]   k = %1", k);
        foreach (auto i, auto v : k)
        PrintFormat("[SHA256]     k[%1] = 0x%2", i, SHA256_Helper.IntToStringHex(v));

        PrintFormat("[SHA256]   chunk_size = %1", chunk_size);
        PrintFormat("[SHA256]   chunk_word_size = %1", chunk_word_size);
        PrintFormat("[SHA256]   chunk_words_count = %1", chunk_words_count);
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
        int l = L % chunk_size;
        int i = l / chunk_word_size;
        int j = chunk_word_size - (l % chunk_word_size) - 1;
        chunk[i] = (chunk[i] & ~(1 << j)) | (bit << j);
        L++;
		if (L % chunk_size == 0)
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
        for (int i = 0; i < n / chunk_word_size; i++)
            PushBitsV(bits[i], chunk_word_size);
        PushBitsV(bits[n / chunk_word_size], n % chunk_word_size);
    };

    void PushBitsV(notnull array<int> bits, int n) {
        for (int i = 0; i < n / chunk_word_size; i++)
            PushBitsV(bits[i], chunk_word_size);
        PushBitsV(bits[n / chunk_word_size], n % chunk_word_size);
    };

	void PushBytesV(notnull array<int> bytes, int n) {
		for (int i = 0; i < n / 8; i++)
			PushByte(bytes[i]);
		PushBitsV(bytes[n / 8], n % 8);
	};


    // Push words (32 bits)
    void PushWord(int word) {
		PushBitsV(word, chunk_word_size);
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

    void PushChunk(int chunk[chunk_words_count]) {
        for (int i = 0; i < chunk_words_count; i++)
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

        auto hash = new SHA256(h);

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

        int L0 = L;
        int h0[h_count];
		for (int i = 0; i < h_count; i++)
            h0[i] = h[i];
        #ifdef SHA256_ZERO_CHUNK
        int chunk0[chunk_words_count]
        for (int i = 0; i < chunk_words_count; i++)
            chunk0[i] = chunk[i];
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

        auto hash = new SHA256(h);

        #ifdef SHA256_DEBUG
        PrintFormat("[SHA256] %1: Hashed!", this);
        PrintFormat("[SHA256]   hash = %1 (0x%2)", hash, hash.AsString());
        #endif

        L = L0;
		for (int i = 0; i < h_count; i++)
            h[i] = h0[i];
        #ifdef SHA256_ZERO_CHUNK
        for (int i = 0; i < chunk_words_count; i++)
            chunk[i] = chunk0[i];
        #endif

        #ifdef SHA256_DEBUG_V_V
        PrintFormat("[SHA256]   Restored state:");
		PrintFormat("[SHA256]     L = %1", L);
		PrintFormat("[SHA256]     h = %1", h);
		foreach (auto i, auto v : h0)
		 	PrintFormat("[SHA256]      h[%1] = 0x%2", i, SHA256_Helper.IntToStringHex(v));
        #ifdef SHA256_ZERO_CHUNK
		PrintFormat("[SHA256]     chunk = %1", chunk);
		foreach (auto i, auto v : chunk)
		 	PrintFormat("[SHA256]      chunk[%1] = 0x%2", i, SHA256_Helper.IntToStringHex(v));
        #endif
        #endif

        return hash;
    };

    void Reset() {
        #ifdef SHA256_DEBUG
        PrintFormat("[SHA256] %1: Resetting...", this);
        #endif

		foreach (auto i, auto v : h_init)
			h[i] = v;

        #ifdef SHA256_DEBUG_V_V
		PrintFormat("[SHA256]   h = %1", h);
		foreach (auto i, auto v : h)
		 	PrintFormat("[SHA256]      h[%1] = 0x%2", i, SHA256_Helper.IntToStringHex(v));
        #endif

		L = 0;

        #ifdef SHA256_DEBUG_V_V
		PrintFormat("[SHA256]   L = %1", L);
        #endif

        #ifdef SHA256_ZERO_CHUNK
		foreach (auto i, auto v : chunk)
            chunk[i] = 0x00000000;

        #ifdef SHA256_DEBUG_V_V
		PrintFormat("[SHA256]   chunk = %1", chunk);
        foreach (auto i, auto v : chunk)
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
		while ((L + 1 + K + 64) % chunk_size != 0)
			K++;

        #ifdef SHA256_DEBUG_V_V
        PrintFormat("[SHA256]     L = %1", L);
        PrintFormat("[SHA256]     K = %1", K);
        #endif

		auto l = L;
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
		auto n = L / chunk_size - 1;
		PrintFormat("[SHA256]   %1: Processing chunk #%2...", this, n);
        #endif

        #ifdef SHA256_DEBUG_V_V
        PrintFormat("[SHA256]     chunk = %1", chunk);
		foreach (auto i, auto v : chunk)
			PrintFormat("[SHA256]       chunk[%1] = 0x%2", i, SHA256_Helper.IntToStringHex(v));
		#endif

        #ifdef SHA256_DEBUG_V_V_V_V
        PrintFormat("[SHA256]     Scheduling...");
        #endif

        int w[k_count];

        for (int i = 0; i < chunk_words_count; i++) {
            w[i] = chunk[i];
            #ifdef SHA256_DEBUG_V_V_V_V
		    PrintFormat("[SHA256]       i = %1", i);
		    PrintFormat("[SHA256]         w[i] = 0x%1", SHA256_Helper.IntToStringHex(w[i]));
            #endif
        };

        for (int i = chunk_words_count; i < k_count; i++) {
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

        int v[h_count];
        for (int i = 0; i < h_count; i++)
            v[i] = h[i];

		#ifdef SHA256_DEBUG_V_V_V
        PrintFormat("[SHA256]   Compression...");
		PrintFormat("[SHA256]     v = %1", v);
		foreach (auto i, auto x : v)
			PrintFormat("[SHA256]       v[%1] = 0x%2", i, SHA256_Helper.IntToStringHex(x));
		#endif

        for (int i = 0; i < k_count; i++) {
            // #ifdef SHA256_DEBUG_V_V
            // PrintFormat("[SHA256]     %1: Processing compression step %2...", this, i);
            // #endif

            int S1 = SHA256_Helper.rotr(v[4], 6) ^ SHA256_Helper.rotr(v[4], 11) ^ SHA256_Helper.rotr(v[4], 25);
            int ch = (v[4] & v[5]) ^ ((~v[4]) & v[6]);
            int temp1 = v[7] + S1 + ch + k[i] + w[i];
            int S0 = SHA256_Helper.rotr(v[0], 2) ^ SHA256_Helper.rotr(v[0], 13) ^ SHA256_Helper.rotr(v[0], 22);
            int maj = (v[0] & v[1]) ^ (v[0] & v[2]) ^ (v[1] & v[2]);
            int temp2 = S0 + maj;

            // #ifdef SHA256_DEBUG_V_V
            // PrintFormat("[SHA256]         S1 = %1", SHA256_Helper.IntToStringHex(S1));
            // PrintFormat("[SHA256]         ch = %1", SHA256_Helper.IntToStringHex(ch));
            // PrintFormat("[SHA256]         temp1 = %1", SHA256_Helper.IntToStringHex(temp1));
            // PrintFormat("[SHA256]         S0 = %1", SHA256_Helper.IntToStringHex(S0));
            // PrintFormat("[SHA256]         maj = %1", SHA256_Helper.IntToStringHex(maj));
            // PrintFormat("[SHA256]         temp2 = %1", SHA256_Helper.IntToStringHex(temp2));
            // #endif

            v[7] = v[6];
            v[6] = v[5];
            v[5] = v[4];
            v[4] = v[3] + temp1;
            v[3] = v[2];
            v[2] = v[1];
            v[1] = v[0];
            v[0] = temp1 + temp2;

            // #ifdef SHA256_DEBUG_V_V
            // PrintFormat("[SHA256]     %1: Intermediate working variables:", this);
		    // for (int j = 0; j < 8; j++)
			//     PrintFormat("[SHA256]         v[%1] = 0x%2", j, SHA256_Helper.IntToStringHex(v[j]));
            // #endif
        };

		#ifdef SHA256_DEBUG_V_V_V
        PrintFormat("[SHA256]   Compressed!");
		PrintFormat("[SHA256]     v = %1", v);
		foreach (auto i, auto x : v)
			PrintFormat("[SHA256]       v[%1] = 0x%2", i, SHA256_Helper.IntToStringHex(x));
		#endif

        for (int i = 0; i < 8; i++)
            h[i] = h[i] + v[i];

		#ifdef SHA256_DEBUG_V_V_V
		PrintFormat("[SHA256]     h = %1", h);
		foreach (auto i, auto x : h)
			PrintFormat("[SHA256]       h[%1] = 0x%2", i, SHA256_Helper.IntToStringHex(x));
		#endif

		#ifdef SHA256_DEBUG
		PrintFormat("[SHA256]   Chunk process completed!", n);
		#endif
    };
};

class SHA256_Helper {
    static const int byte_size = 8;

    static const int byte_mask = 0xFF;

    static const int byte_half_size = 4;

    static const int byte_half_mask = 0x0F;

    static const int int_size = 4;

    static const int int_size_bits = int_size * byte_size;

    static const int int_sign_mask = 0x80000000;

    static const string hex = "0123456789abcdef";

	// rotate right
	static int rotr(int x, int n) {
	    return shr(x, n) | (x << (int_size_bits - n));
	};

	// shift right logical
	static int shr(int x, int n) {
	    if (x < 0)
			return ((x & ~int_sign_mask) >> n) | (1 << (int_size_bits - n - 1));
	    return x >> n;
	};

	static string IntToStringHex(int x) {
		auto result = "";
	    for (int i = 0; i < int_size; i++) {
	        auto byte = (x >> ((int_size - i - 1) * byte_size)) & byte_mask;
	        result += hex[byte >> byte_half_size];
	        result += hex[byte & byte_half_mask];
	    };
		return result;
	};
};
