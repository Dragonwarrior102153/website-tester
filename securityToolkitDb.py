import sqlite3

class secToolDb():
    def __init__(self) -> None:
        query = """
                CREATE TABLE IF NOT EXISTS targets(
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
        self.allowedTables = []

    def create(self, name, url, time) -> None:
        query = "INSERT INTO targets VALUES (?,?,?)"
        self.cursor.execute(query, (name, url, time))
        self.conn.commit()

    def read(self, id) -> list:
        query = "SELECT * FROM targets WHERE (ID = ?)"
        self.cursor.execute(query, (id,))
        return self.cursor.fetchone()

    def readAll(self) -> list:
        query = "SELECT * FROM targets"
        self.cursor.execute(query)
        return self.cursor.fetchall()

    def updateRow(self, id, name, url, time) -> None:
        query = "UPDATE targets SET Name = ?, URL = ?, Time = ? WHERE (ID = ?)"
        self.cursor.execute(query, (name, url, time, id))

    def update(self, id, column, value) -> None:
        if (column in self.allowedColumns):
            query = f"UPDATE targets SET {column} = ? WHERE (ID = ?)"
            self.cursor.execute(query, (value, id))

    def delete(self, id) -> None:
        query = "DELETE FROM targets WHERE (ID = ?)"
        self.cursor.execute(query, (id,))
        self.conn.commit()

    def deleteTable(self, table) -> None:
        query = f"DROP TABLE {table}"
        self.cursor.execute(query)
        self.conn.commit()

    def disconnect(self) -> None:
        self.conn.close()