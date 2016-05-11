from sqlalchemy import text
from keystone.common import sql

class DatabaseCheck():
    def check_connection(self):
        try:
            engine = sql.get_engine()
            sql_text = text('SELECT 1;')
            result = engine.execute(sql_text)
        except Exception:
            return False
        return True

    def check_wsrep(self):
        try:
            engine = sql.get_engine()
            sql_text = text('SELECT VARIABLE_VALUE as "cluster size" FROM INFORMATION_SCHEMA.GLOBAL_STATUS WHERE VARIABLE_NAME="wsrep_cluster_size";')
            result = engine.execute(sql_text)
        except Exception:
            return -1
        return result.rowcount


    def check_tables(self):
        try:
            engine = sql.get_engine()
            sql_text = text('show tables;')
            result = engine.execute(sql_text)
            if result.rowcount == 0:
                return None
            else:
                result_list = []
                for row in result:
                    result_list.append(row[0])
                return result_list
        except Exception:
            return None

