from pydantic import BaseModel


class NetworkEvent(BaseModel):

    # Basic connection features
    dur: float
    proto: str
    service: str
    state: str

    # Packet features
    spkts: int
    dpkts: int
    sbytes: int
    dbytes: int
    rate: float

    # TTL features
    sttl: int
    dttl: int

    # Load features
    sload: float
    dload: float

    # Loss features
    sloss: int
    dloss: int

    # Packet timing features
    sinpkt: float
    dinpkt: float
    sjit: float
    djit: float

    # TCP window features
    swin: int
    stcpb: int
    dtcpb: int
    dwin: int

    # TCP timing features
    tcprtt: float
    synack: float
    ackdat: float

    # Packet size features
    smean: int
    dmean: int

    # HTTP features
    trans_depth: int
    response_body_len: int

    # Connection count features
    ct_srv_src: int
    ct_state_ttl: int
    ct_dst_ltm: int
    ct_src_dport_ltm: int
    ct_dst_sport_ltm: int
    ct_dst_src_ltm: int

    # FTP / HTTP features
    is_ftp_login: int
    ct_ftp_cmd: int
    ct_flw_http_mthd: int

    # Additional connection features
    ct_src_ltm: int
    ct_srv_dst: int

    # IP / port behavior
    is_sm_ips_ports: int
    def to_dict(self):
        return self.model_dump()