import sqlite3

class SecToolDb():
    def __init__(self, table) -> None:
        self.table = table
        query = f"""
                CREATE TABLE IF NOT EXISTS {self.table}(
                ID INT PRIMARY KEY,
                Name TEXT NOT NULL,
                URL TEXT NOT NULL,
                Time TEXT
                )
                """
        self.conn = sqlite3.connect('SecurityToolkitDb')
        self.cursor = self.conn.cursor()
        self.cursor.execute(query)
        self.conn.commit()

        self.allowedColumns = []

    def create(self, name, url, time) -> None:
        query = f"INSERT INTO {self.table} VALUES (?,?,?)"
        self.cursor.execute(query, (name, url, time))
        self.conn.commit()

    def read(self, id) -> list:
        query = f"SELECT * FROM {self.table} WHERE (ID = ?)"
        self.cursor.execute(query, (id,))
        return self.cursor.fetchone()

    def readAll(self) -> list:
        query = f"SELECT * FROM {self.table}"
        self.cursor.execute(query)
        return self.cursor.fetchall()

    def updateRow(self, id, name, url, time) -> None:
        query = f"UPDATE {self.table} SET Name = ?, URL = ?, Time = ? WHERE (ID = ?)"
        self.cursor.execute(query, (name, url, time, id))

    def update(self, id, column, value) -> None:
        if (column in self.allowedColumns):
            query = f"UPDATE {self.table} SET {column} = ? WHERE (ID = ?)"
            self.cursor.execute(query, (value, id))

    def delete(self, id) -> None:
        query = f"DELETE FROM {self.table} WHERE (ID = ?)"
        self.cursor.execute(query, (id,))
        self.conn.commit()

    def deleteTable(self) -> None:
        query = f"DROP TABLE {self.table}"
        self.cursor.execute(query)
        self.conn.commit()

    def disconnect(self) -> None:
        self.conn.close()