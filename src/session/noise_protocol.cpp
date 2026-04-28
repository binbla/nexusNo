
bool NoiseProtocol::create_initiation(Peer& peer, KeypairIndex local_index,
                                      HandshakeInitiation& msg) {
    if (!initialized_) {
        return false;
    }

    Handshake& hs = peer.handshake();

    // ------------------------------------------------------------
    // 初始化消息头
    // ------------------------------------------------------------
    msg.message_type = MessageType::HandshakeInitiation;
    msg.sender_index = local_index;
    msg.ephemeral_public.fill(0);
    msg.static_encrypted.fill(0);
    msg.timestamp_encrypted.fill(0);
    msg.mac1.fill(0);
    msg.mac2.fill(0);

    // ------------------------------------------------------------
    // Ci := Hash(Construction)
    // Hi := Hash(Ci || Identifier)
    // Hi := Hash(Hi || Spub_r)
    // ------------------------------------------------------------
    if (!noise::initialize_handshake_from_base(base_chaining_key_, base_hash_,
                                               peer.remote_static(),  // Spub_r
                                               hs.chaining_key,       // Ci
                                               hs.hash)) {            // Hi
        return false;
    }

    // ------------------------------------------------------------
    // (Epriv_i, Epub_i) := DH-Generate()
    // msg.ephemeral := Epub_i
    // ------------------------------------------------------------
    if (!crypto::generate_ephemeral_keypair(hs.ephemeral_private,     // Epriv_i
                                            msg.ephemeral_public)) {  // Epub_i
        return false;
    }

    // 如果 Handshake 里有本地 ephemeral public，也可以保存一份
    hs.local_ephemeral = msg.ephemeral_public;

    // ------------------------------------------------------------
    // Ci := Kdf1(Ci, Epub_i)
    // Hi := Hash(Hi || msg.ephemeral)
    // ------------------------------------------------------------
    noise::mix_ephemeral(msg.ephemeral_public, hs.chaining_key, hs.hash);

    SymmetricKey key{};

    // ------------------------------------------------------------
    // es:
    // (Ci, κ) := Kdf2(Ci, DH(Epriv_i, Spub_r))
    // ------------------------------------------------------------
    if (!noise::mix_dh(hs.chaining_key, key,
                       hs.ephemeral_private,     // Epriv_i
                       peer.remote_static())) {  // Spub_r
        crypto::secure_zero(key);
        return false;
    }

    // ------------------------------------------------------------
    // msg.static := Aead(κ, 0, Spub_i, Hi)
    // Hi := Hash(Hi || msg.static)
    // ------------------------------------------------------------
    if (!noise::encrypt_and_hash(msg.static_encrypted,
                                 local_public_,  // Spub_i
                                 key, hs.hash)) {
        crypto::secure_zero(key);
        return false;
    }

    // ------------------------------------------------------------
    // ss:
    // (Ci, κ) := Kdf2(Ci, DH(Spriv_i, Spub_r))
    // ------------------------------------------------------------
    if (!noise::mix_precomputed_dh(hs.chaining_key, key,
                                   peer.precomputed_static_static())) {
        crypto::secure_zero(key);
        return false;
    }

    // ------------------------------------------------------------
    // msg.timestamp := Aead(κ, 0, Timestamp(), Hi)
    // Hi := Hash(Hi || msg.timestamp)
    // ------------------------------------------------------------
    Timestamp timestamp = tai64n_now();

    if (!noise::encrypt_and_hash(msg.timestamp_encrypted, timestamp, key,
                                 hs.hash)) {
        crypto::secure_zero(key);
        return false;
    }

    // ------------------------------------------------------------
    // 保存握手状态
    // ------------------------------------------------------------
    hs.local_index = local_index;
    hs.remote_static = peer.remote_static();
    hs.state = HandshakeState::CreatedInitiation;

    crypto::secure_zero(key);
    return true;
}