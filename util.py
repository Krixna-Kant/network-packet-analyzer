def build_filter(protocol=None, src_ip=None, dst_ip=None, port=None):
    filters=[]
    if protocol:
        filters.append(protocol.lower())
    if src_ip:
        filters.append(f"src host {src_ip}")
    if dst_ip:
        filters.append(f"dst host {dst_ip}")
    if port:
        filters.append(f"port {port}")
    return ' and '.join(filters)