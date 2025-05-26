import base64

def pqxdh_bundle_to_wire(bundle, private_keys):
    # Convert all bytes to base64 strings for storage/networking
    def b64(x):
        if isinstance(x, bytes):
            return base64.b64encode(x).decode()
        if isinstance(x, (list, frozenset)):
            return [b64(i) for i in x]
        return x
    bndl = bundle.copy()
    bndl['x3dh_bundle'] = {k: b64(v) for k, v in bundle['x3dh_bundle'].items()}
    bndl['kyber1024_identity'] = b64(bundle['kyber1024_identity'])
    priv = private_keys.copy()
    priv['x3dh_state'] = private_keys['x3dh_state']
    priv['kyber1024'] = b64(private_keys['kyber1024'])
    return bndl, priv

def pqxdh_bundle_from_wire(bundle, priv):
    def b64d(x):
        if isinstance(x, str):
            return base64.b64decode(x)
        if isinstance(x, list):
            return [b64d(i) for i in x]
        return x
    bndl = bundle.copy()
    bndl['x3dh_bundle'] = {k: b64d(v) for k, v in bundle['x3dh_bundle'].items()}
    bndl['kyber1024_identity'] = b64d(bundle['kyber1024_identity'])
    privd = priv.copy()
    privd['x3dh_state'] = priv['x3dh_state']
    privd['kyber1024'] = b64d(priv['kyber1024'])
    return bndl, privd

def pqxdh_peer_bundle_to_wire(bundle, kyber_pub):
    def b64(x):
        if isinstance(x, bytes):
            return base64.b64encode(x).decode()
        if isinstance(x, (list, frozenset)):
            return [b64(i) for i in x]
        return x
    return {
        'x3dh_bundle': {k: b64(v) for k, v in bundle._asdict().items()},
        'kyber1024_identity': b64(kyber_pub)
    }

def pqxdh_peer_bundle_from_wire(bundle):
    def b64d(x):
        if isinstance(x, str):
            return base64.b64decode(x)
        if isinstance(x, list):
            return [b64d(i) for i in x]
        return x
    peer_bundle = {k: b64d(v) for k, v in bundle['x3dh_bundle'].items()}
    kyber_pub = b64d(bundle['kyber1024_identity'])
    return {'x3dh_bundle': peer_bundle, 'kyber1024_identity': kyber_pub}
