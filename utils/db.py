import mysql.connector
from mysql.connector import Error
from config import Config


def get_connection():
    return mysql.connector.connect(
        host=Config.DB_HOST,
        user=Config.DB_USER,
        password=Config.DB_PASSWORD,
        database=Config.DB_NAME,
        port=Config.DB_PORT
    )


def fetch_all(query, params=None):
    conn = get_connection()
    cursor = conn.cursor(dictionary=True)
    cursor.execute(query, params or ())
    rows = cursor.fetchall()
    cursor.close()
    conn.close()
    return rows


def fetch_one(query, params=None):
    conn = get_connection()
    cursor = conn.cursor(dictionary=True)
    cursor.execute(query, params or ())
    row = cursor.fetchone()
    cursor.close()
    conn.close()
    return row


def execute_query(query, params=None, many=False):
    conn = get_connection()
    cursor = conn.cursor()
    try:
        if many:
            cursor.executemany(query, params)
        else:
            cursor.execute(query, params or ())
        conn.commit()
        last_id = cursor.lastrowid
        return last_id
    except Error:
        conn.rollback()
        raise
    finally:
        cursor.close()
        conn.close()