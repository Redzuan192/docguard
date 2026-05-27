from utils.db import execute_query


def add_log(user_id, action, description, ip_address=None, file_id=None):
    query = """
        INSERT INTO audit_logs (user_id, file_id, action, description, ip_address)
        VALUES (%s, %s, %s, %s, %s)
    """
    execute_query(query, (user_id, file_id, action, description, ip_address))