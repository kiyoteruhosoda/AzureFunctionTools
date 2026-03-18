import azure.functions as func
import json
import logging
import ipaddress

bp = func.Blueprint()

def extract_ip_list(ip_header: str) -> list[str]:
    """ヘッダー文字列からIPアドレスリストを抽出"""
    ip_list: list[str] = []
    if ip_header:
        for ip_entry in ip_header.split(","):
            ip_only = ip_entry.strip()
            # IPv6アドレス中の:は除去しないが、ポート区切りを削除
            if ":" in ip_only and not ip_only.count(":") > 1:
                ip_only = ip_only.split(":")[0]
            ip_list.append(ip_only)
    return ip_list


def filter_ip_list(ip_list: list[str], version: str) -> list[str]:
    """IPv4/IPv6でフィルタリング"""
    result: list[str] = []
    for ip in ip_list:
        try:
            ip_obj = ipaddress.ip_address(ip)
        except ValueError:
            continue

        if version == "ipv4" and isinstance(ip_obj, ipaddress.IPv4Address):
            result.append(ip)
        elif version == "ipv6" and isinstance(ip_obj, ipaddress.IPv6Address):
            result.append(ip)
        elif version == "all":
            result.append(ip)

    return result

@bp.route(route="GlobalIp", methods=["GET"], auth_level=func.AuthLevel.ANONYMOUS)
def GlobalIp(req: func.HttpRequest) -> func.HttpResponse:
    logging.info("Processing IP detection request...")

    # クエリパラメータ取得
    version = (req.params.get("version") or "all").lower()  # ipv4 / ipv6 / all
    limit_param = req.params.get("filter")  # 件数指定（例: ?filter=3）
    limit: int | None = None
    if limit_param and limit_param.isdigit():
        limit = int(limit_param)

    # X-Forwarded-For優先
    ip_header = req.headers.get("X-Forwarded-For", req.headers.get("x-forwarded-for"))
    ip_list = extract_ip_list(ip_header)
    if not ip_list:
        ip_header = req.headers.get("X-Real-IP", req.headers.get("x-real-ip"))
        ip_list = extract_ip_list(ip_header)

    # バージョンフィルタ
    filtered_ips = filter_ip_list(ip_list, version)

    # 件数制限
    if limit is not None:
        filtered_ips = filtered_ips[:limit]

    # 結果
    if not filtered_ips:
        result = {"ip": "unknown"}
    elif len(filtered_ips) == 1:
        result = {"ip": filtered_ips[0]}
    else:
        result = {"ip": filtered_ips}

    return func.HttpResponse(
        json.dumps(result, ensure_ascii=False, indent=2),
        mimetype="application/json",
        status_code=200,
    )