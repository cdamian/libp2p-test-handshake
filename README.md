# libp2p test handshake config

This `Rust` library contains a small and simple p2p handshake mechanism that can be used with the [Rust p2p library](https://github.com/libp2p/rust-libp2p).

The handshake information that is sent in JSON format contains the public key of the p2p node and a signature that is obtained by signing
the p2p peer ID which in turn is created from the public key. The receiver of the handshake information confirms that the signature is valid by
creating the p2p peer from the provided public key and then using the public key to verify the signature.