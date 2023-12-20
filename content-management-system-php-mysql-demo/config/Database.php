<?php
class Database{
    private $host = 'localhost';
    private $user = 'root';
    private $password = '';
    private $database = 'phpzag_demo';

    public function getConnection(){
        try {
            $dsn = "mysql:host={$this->host};dbname={$this->database};charset=utf8";
            $options = [
                PDO::ATTR_ERRMODE => PDO::ERRMODE_EXCEPTION,
                PDO::ATTR_DEFAULT_FETCH_MODE => PDO::FETCH_ASSOC,
                PDO::ATTR_EMULATE_PREPARES => false,
            ];

            $pdo = new PDO($dsn, $this->user, $this->password, $options);

            return $pdo;
        } catch (PDOException $e) {
            die("Error failed to connect to MySQL: " . $e->getMessage());
        }
    }
}
?>
