<?php
/* Database connection start */
$servername = "localhost";
$username = "root";
$password = "";
$database = "MittreAttackChecker";
$conn = mysqli_connect($servername, $username, $password) or die("Connection failed: " . mysqli_connect_error());
if (mysqli_connect_errno()) {
    printf("Connect failed: %s\n", mysqli_connect_error());
    exit();
}
// Create database
$sql = "CREATE DATABASE MittreAttackChecker";
if ($conn->query($sql) === TRUE) {
    echo "Database created successfully";
	echo "<br>";
	echo "<br>";
} else {
    echo "Error creating database: " . $conn->error;
	echo "<br>";
	echo "<br>";
}
$conn->close();

// sql to create table
$sql = "CREATE TABLE ThreatData (
ID int NOT NULL AUTO_INCREMENT,
ID1 VARCHAR(255),
ID2 VARCHAR(255),
ID3 VARCHAR(255),
ID4 VARCHAR(255),
ID5 TEXT,
ID6 VARCHAR(255),
ID7 VARCHAR(255),
ID8 VARCHAR(255),
UNIQUE (ID)
) ENGINE=InnoDB CHARACTER SET=utf8; ";

$conn = mysqli_connect($servername, $username, $password, $database) or die("Connection failed: " . mysqli_connect_error());
if (mysqli_connect_errno()) {
    printf("Connect failed: %s\n", mysqli_connect_error());
    exit();
}

if ($conn->query($sql) === TRUE) {
    echo "Table ThreatData created successfully";
	echo "<br>";
	echo "<br>";
} else {
    echo "Error creating table: " . $conn->error;
	echo "<br>";
	echo "<br>";
}

$conn->close();

?>