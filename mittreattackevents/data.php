<?php
include_once("db_connect.php");
$sql = "SELECT ID as ID, ID1 as ID1, ID2 as ID2, ID3 as ID3, ID4 as ID4, ID5 as ID5, ID6 as ID6, ID7 as ID7, ID8 as ID8 FROM ThreatData LIMIT 1000000000";
$resultset = mysqli_query($conn, $sql) or die("database error:". mysqli_error($conn));
$data = array();
while( $rows = mysqli_fetch_assoc($resultset) ) {
	$data[] = $rows;
}

$results = array(
	"sEcho" => 1,
"iTotalRecords" => count($data),
"iTotalDisplayRecords" => count($data),
  "aaData"=>$data);

echo json_encode($results);

?>
