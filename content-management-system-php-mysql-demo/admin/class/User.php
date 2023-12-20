<?php
class User {    
    private $userTable = 'cms_user';
    private $conn;
    public $id;
    public $first_name;
    public $last_name;
    public $email;
    public $password;
    public $type;
    public $deleted;

    public function __construct($db){
        $this->conn = $db;
    }       

    public function login(){
        if($this->email && $this->password) {
            $sqlQuery = "
                SELECT * FROM ".$this->userTable." 
                WHERE email = ? AND password = ?";            
            $stmt = $this->conn->prepare($sqlQuery);
            $stmt->execute([$this->email, md5($this->password)]);
            $user = $stmt->fetch(PDO::FETCH_ASSOC);

            if($user){
                $_SESSION["userid"] = $user['id'];
                $_SESSION["user_type"] = $user['type'];
                $_SESSION["name"] = $user['first_name']." ".$user['last_name'];                   
                return 1;       
            } else {
                return 0;       
            }            
        } else {
            return 0;
        }
    }

    public function loggedIn (){
        if(!empty($_SESSION["userid"])) {
            return 1;
        } else {
            return 0;
        }
    }

    public function totalUser(){        
        $sqlQuery = "SELECT * FROM ".$this->userTable;            
        $stmt = $this->conn->prepare($sqlQuery);            
        $stmt->execute();
        $result = $stmt->fetchAll(PDO::FETCH_ASSOC);
        return count($result);    
    }   

    public function getUsersListing(){        
        $whereQuery = '';
        if($_SESSION['user_type'] == 2) {
            $whereQuery = "WHERE id = :userid";
        }        

        $sqlQuery = "
            SELECT id, first_name, last_name, email, type, deleted
            FROM ".$this->userTable."  
            $whereQuery ";

        if(!empty($_POST["search"]["value"])){
            $sqlQuery .= ' first_name LIKE :search OR last_name LIKE :search OR email LIKE :search OR type LIKE :search';
        }
        if(!empty($_POST["order"])){
            $sqlQuery .= ' ORDER BY ' . $_POST['order']['0']['column'] . ' ' . $_POST['order']['0']['dir'];
        } else {
            $sqlQuery .= ' ORDER BY id DESC';
        }
        if($_POST["length"] != -1){
            $sqlQuery .= ' LIMIT ' . $_POST['start'] . ', ' . $_POST['length'];
        }

        $stmt = $this->conn->prepare($sqlQuery);

        if($_SESSION['user_type'] == 2) {
            $stmt->bindParam(':userid', $_SESSION['userid'], PDO::PARAM_INT);
        }

        if(!empty($_POST["search"]["value"])){
            $stmt->bindValue(':search', '%' . $_POST["search"]["value"] . '%', PDO::PARAM_STR);
        }

        $stmt->execute();
        $result = $stmt->fetchAll(PDO::FETCH_ASSOC);    

        $stmtTotal = $this->conn->prepare("SELECT * FROM ".$this->userTable);
        $stmtTotal->execute();
        $allResult = $stmtTotal->fetchAll(PDO::FETCH_ASSOC);
        $allRecords = count($allResult);

        $displayRecords = count($result);
        $users = array();

        foreach ($result as $user) {
            $rows = array();    
            $status = ($user['deleted']) ? '<span class="label label-danger">Inactive</span>' : '<span class="label label-success">Active</span>';

            $type = ($user['type'] == 1) ? '<span class="label label-danger">Admin</span>' : '<span class="label label-warning">Author</span>';

            $rows[] = ucfirst($user['first_name'])." ".$user['last_name'];
            $rows[] = $user['email'];
            $rows[] = $type;
            $rows[] = $status;
            $rows[] = '<a href="add_users.php?id='.$user["id"].'" class="btn btn-warning btn-xs update">Edit</a>';
            $rows[] = '<button type="button" name="delete" id="'.$user["id"].'" class="btn btn-danger btn-xs delete" >Delete</button>';
            $users[] = $rows;
        }

        $output = array(
            "draw"  =>  intval($_POST["draw"]),           
            "iTotalRecords" =>  $displayRecords,
            "iTotalDisplayRecords"  =>  $allRecords,
            "data"  =>  $users
        );

        echo json_encode($output);    
    }

    public function getUser(){        
        if($this->id) {
            $sqlQuery = "
            SELECT id, first_name, last_name, email, type, deleted
            FROM ".$this->userTable."           
            WHERE id = :userid ";
            $stmt = $this->conn->prepare($sqlQuery);
            $stmt->bindParam(':userid', $this->id, PDO::PARAM_INT);
            $stmt->execute();
            $result = $stmt->fetch(PDO::FETCH_ASSOC);
            return $result;
        }       
    }

    public function insert(){
        if($this->email && $this->password) {
            $stmt = $this->conn->prepare("
                INSERT INTO ".$this->userTable."(`first_name`, `last_name`, `email`, `password`, `type`, `deleted`)
                VALUES(:first_name, :last_name, :email, :password, :type, :deleted)");

            $this->first_name = htmlspecialchars(strip_tags($this->first_name));
            $this->last_name = htmlspecialchars(strip_tags($this->last_name));
            $this->email = htmlspecialchars(strip_tags($this->email));
            $this->password = htmlspecialchars(strip_tags(md5($this->password)));
            $this->type = htmlspecialchars(strip_tags($this->type));
            $this->deleted = htmlspecialchars(strip_tags($this->deleted));       

            $stmt->bindParam(':first_name', $this->first_name, PDO::PARAM_STR);
            $stmt->bindParam(':last_name', $this->last_name, PDO::PARAM_STR);
            $stmt->bindParam(':email', $this->email, PDO::PARAM_STR);
            $stmt->bindParam(':password', $this->password, PDO::PARAM_STR);
            $stmt->bindParam(':type', $this->type, PDO::PARAM_INT);
            $stmt->bindParam(':deleted', $this->deleted, PDO::PARAM_INT);

            if($stmt->execute()){
                return $this->conn->lastInsertId();
            }       
        }
    }

    public function update(){
        if($this->id) {           
            $stmt = $this->conn->prepare("
                UPDATE ".$this->userTable." 
                SET first_name= :first_name, last_name = :last_name, email = :email, type = :type, deleted= :deleted
                WHERE id = :userid");

            $this->id = htmlspecialchars(strip_tags($this->id));
            $this->first_name = htmlspecialchars(strip_tags($this->first_name));
            $this->last_name = htmlspecialchars(strip_tags($this->last_name));
            $this->email = htmlspecialchars(strip_tags($this->email));
            $this->type = htmlspecialchars(strip_tags($this->type));
            $this->deleted = htmlspecialchars(strip_tags($this->deleted));

            $stmt->bindParam(':first_name', $this->first_name, PDO::PARAM_STR);
            $stmt->bindParam(':last_name', $this->last_name, PDO::PARAM_STR);
            $stmt->bindParam(':email', $this->email, PDO::PARAM_STR);
            $stmt->bindParam(':type', $this->type, PDO::PARAM_INT);
            $stmt->bindParam(':deleted', $this->deleted, PDO::PARAM_INT);
            $stmt->bindParam(':userid', $this->id, PDO::PARAM_INT);

            if($stmt->execute()){
                return true;
            }           
        }
    }

    public function delete(){
        if($this->id) {    
            $stmt = $this->conn->prepare("
                DELETE FROM ".$this->userTable."                 
                WHERE id = :userid");

            $this->id = htmlspecialchars(strip_tags($this->id));
            $stmt->bindParam(':userid', $this->id, PDO::PARAM_INT);

            if($stmt->execute()){
                return true;
            }
        }
    }
}
?>
