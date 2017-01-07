<?php
/*
* This file is part of Lair.
*
* Lair is free software: you can redistribute it and/or modify
* it under the terms of the GNU General Public License as published by
* the Free Software Foundation, either version 3 of the License, or
* (at your option) any later version.
*
* Lair is distributed in the hope that it will be useful,
* but WITHOUT ANY WARRANTY; without even the implied warranty of
* MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
* GNU General Public License for more details.
*
* You should have received a copy of the GNU General Public License
* along with Lair. If not, see <http://www.gnu.org/licenses/>.
*/

$base64pubencoded = "data in base64 format here";
if(isset($_POST['base64encoded'])) $base64encoded = $_POST['base64encoded'];
$data = base64_decode($base64encoded);
$arraydata = str_split($data, 128);

$fp = fopen("/var/www/router.loso.sk/S_id_rsa", "r");
$S_id_rsa = fread($fp, 8192);
fclose($fp);

include_once "/var/www/router.loso.sk/LairSEC.php";

$res = openssl_get_privatekey($S_id_rsa, $passphrase);

$text0 = "";
$text2 = "";
for($i = 0; $i < count($arraydata); $i ++) {
 if(openssl_private_decrypt($arraydata[$i], $text1, $res)) {
  $text0 .= $text1;
  $N_UUID = substr($text1, 1, 36);
  $pktid = substr($text1, 0, 1);
  $pktkeypart = substr($text1, 37);
 
  $p0 = "";
  $p1 = "";
  $p2 = "";
  $p3 = "";
  $paired = 0;
 
  if($N_UUID[8] == '-') { // Is this really N_UUID string?
   $query = $db->prepare("select * from pdevice where N_UUID = :field0");
   $query->bindParam(':field0', $N_UUID, PDO::PARAM_STR);
   $query->execute();
   if(0 == $query->rowCount()) { // N_UUID is not in pdevice table
    switch ($pktid) {
     case 0: $p0 = $pktkeypart; break;
     case 1: $p1 = $pktkeypart; break;
     case 2: $p2 = $pktkeypart; break;
     case 3: $p3 = $pktkeypart; break;
    }
    $query = $db->prepare("insert into pdevice (N_UUID, p0, p1, p2, p3, paired) values (:field0, :field1, :field2, :field3, :field4, :field5)");
    $query->bindParam(':field0', $N_UUID, PDO::PARAM_STR);
    $query->bindParam(':field1', $p0,     PDO::PARAM_STR);
    $query->bindParam(':field2', $p1,     PDO::PARAM_STR);
    $query->bindParam(':field3', $p2,     PDO::PARAM_STR);
    $query->bindParam(':field4', $p3,     PDO::PARAM_STR);
    $query->bindParam(':field5', $paired, PDO::PARAM_INT);
    $query->execute();
   } else { // N_UUID is known.
    $pdevice = $query->fetch(PDO::FETCH_ASSOC);
    if($pdevice['paired'] == 0) { // device is not paired
     switch ($pktid) {
      case 0:
       if($pdevice['p0'] == "") {
        $query = $db->prepare("update pdevice set p0 = :field0, timestamp = NOW() where N_UUID = :field1");
        $query->bindParam(':field0', $pktkeypart, PDO::PARAM_STR);
        $query->bindParam(':field1', $N_UUID,     PDO::PARAM_STR);
        $query->execute();
       }
       break;
      case 1:
       if($pdevice['p1'] == "") {
        $query = $db->prepare("update pdevice set p1 = :field0, timestamp = NOW() where N_UUID = :field1");
        $query->bindParam(':field0', $pktkeypart, PDO::PARAM_STR);
        $query->bindParam(':field1', $N_UUID,     PDO::PARAM_STR);
        $query->execute();
       }
       break;
      case 2:
       if($pdevice['p2'] == "") {
        $query = $db->prepare("update pdevice set p2 = :field0, timestamp = NOW() where N_UUID = :field1");
        $query->bindParam(':field0', $pktkeypart, PDO::PARAM_STR);
        $query->bindParam(':field1', $N_UUID,     PDO::PARAM_STR);
        $query->execute();
       }
       break;
      case 3:
       if($pdevice['p3'] == "") {
        $query = $db->prepare("update pdevice set p3 = :field0, timestamp = NOW() where N_UUID = :field1");
        $query->bindParam(':field0', $pktkeypart, PDO::PARAM_STR);
        $query->bindParam(':field1', $N_UUID,     PDO::PARAM_STR);
        $query->execute();
       }
       break;
     }
     $query = $db->prepare("select * from pdevice where N_UUID = :field0");
     $query->bindParam(':field0', $N_UUID, PDO::PARAM_STR);
     $query->execute();
     $pdevice = $query->fetch(PDO::FETCH_ASSOC);
     if($pdevice['p0'] != "" && $pdevice['p1'] != "" && $pdevice['p2'] != "" && $pdevice['p3'] != "") {
      $N_id_rsa_pem_pub = $pdevice['p0'].$pdevice['p1'].$pdevice['p2'].$pdevice['p3'];
      $AES128 = bin2hex(openssl_random_pseudo_bytes(16));
      $paired = 1;
      $query = $db->prepare("update pdevice set paired = :field0, timestamp = NOW() where N_UUID = :field1");
      $query->bindParam(':field0', $paired, PDO::PARAM_INT);
      $query->bindParam(':field1', $N_UUID, PDO::PARAM_STR);
      $query->execute();
 
      $AES128 = bin2hex(openssl_random_pseudo_bytes(16));
      $seqnum = -1;
      $fromnode = "";
      $tonode = "";
      $score = 0;
 
      $query = $db->prepare("insert into adevice (N_UUID, AES128, seqnum, fromnode, tonode, score) values (:field0, :field1, :field2, :field3, :field4, :field5)");
      $query->bindParam(':field0', $N_UUID,   PDO::PARAM_STR);
      $query->bindParam(':field1', $AES128,   PDO::PARAM_STR);
      $query->bindParam(':field2', $seqnum,  PDO::PARAM_INT);
      $query->bindParam(':field3', $fromnode, PDO::PARAM_STR);
      $query->bindParam(':field4', $tonode,   PDO::PARAM_STR);
      $query->bindParam(':field5', $score,    PDO::PARAM_INT);
      $query->execute();
 
      $encrypted_aes128_by_N_id_rsa_pem_pub = "";
      openssl_public_encrypt($AES128, $encrypted_aes128_by_N_id_rsa_pem_pub, $N_id_rsa_pem_pub);
      $base64_encrypted_aes128_by_N_id_rsa_pem_pub = base64_encode($encrypted_aes128_by_N_id_rsa_pem_pub);
      echo "$base64_encrypted_aes128_by_N_id_rsa_pem_pub";
     } // end if p0, p1, p2, p3 are no empty
    }
   }
  }
 } else { // no pub key encrypted data
  $query = $db->prepare("select id, N_UUID, AES128, score, seqnum, tonode from adevice order by score desc");
  $query->execute();
  $decdata = "";
  $msghead = "";
  $msgheader = "L";
  $found = 0;
  while(($row = $query->fetch(PDO::FETCH_ASSOC)) && ($msghead != $msgheader)) {
   $decdata = openssl_decrypt($data, 'aes-128-cbc', hex2bin($row['AES128']), OPENSSL_RAW_DATA, hex2bin($row['AES128']));
   $arraydecdata = explode(" ", $decdata);
   $msghead = $arraydecdata[0];
   $seqnum = intval($arraydecdata[1]);
   if($msghead == $msgheader) { // decoded data contains right msgheader
    $found = 1; // AES128 data decoded successfully
//    if(($seqnum > $row['seqnum']) && ($seqnum < (10 + $row['seqnum']))) { // right seqnum state
    if(1) { // right seqnum state
     $decdata = substr($decdata, 2 + strlen($msghead) + strlen($seqnum)); // cut redundant header data
     $score = $row['score'] + 1;
     $query = $db->prepare("update adevice set score = :field1, fromnode = :field2, seqnum = :field3, timestamp = NOW() where id = :field0");
     $query->bindParam(':field0', $row['id'], PDO::PARAM_INT);
     $query->bindParam(':field1', $score,     PDO::PARAM_INT);
     $query->bindParam(':field2', $decdata,   PDO::PARAM_STR);
     $query->bindParam(':field3', $seqnum,   PDO::PARAM_INT);
     $query->execute();
     if($row['tonode'] != "") { // There is prepared tonode payload
      $dataencrypted = openssl_encrypt("Lair ".$row['seqnum']." ".$row['tonode'], 'aes-128-cbc', $row['AES128'], OPENSSL_RAW_DATA, $row['AES128']);
      $base64dataencrypted = base64_encode($dataencrypted);
      $tonode = "";
      $query = $db->prepare("update adevice set tonode = :field1 where id = :field0");
      $query->bindParam(':field0', $row['id'], PDO::PARAM_INT);
      $query->bindParam(':field1', $tonode,    PDO::PARAM_STR);
      $query->execute();
      sleep(1);
      echo "$base64dataencrypted";
     }
    } else { // wrong seqnum
     echo "debug: wrong seqnum $seqnum {$row['seqnum']}\n";
    }
   }
  }
  if($found == 0) { // It looks like other request type, hopefully it begins with N_UUID
   $N_UUID = substr($data, 0, 36);
   if($N_UUID[8] == '-') { // Is this really N_UUID string?
    $tomsg = substr($data, 37);
    $query = $db->prepare("select id, N_UUID, score, seqnum, fromnode, tonode, timestamp from adevice where N_UUID = :field0");
    $query->bindParam(':field0', $N_UUID, PDO::PARAM_STR);
    $query->execute();
    if($row = $query->fetch(PDO::FETCH_ASSOC)) { // returns last known values
     if($tomsg != "") {
      $score = $row['score'] + 1;
      $query = $db->prepare("update adevice set score = :field1, tonode = :field2 where id = :field0");
      $query->bindParam(':field0', $row['id'], PDO::PARAM_INT);
      $query->bindParam(':field1', $score,     PDO::PARAM_INT);
      $query->bindParam(':field2', $tomsg,     PDO::PARAM_STR);
      $query->execute();
      echo "\"{$row['timestamp']}\", \"{$row['fromnode']}\", \"$tomsg\"\n";
     } else { // there is no request to change tonode value
      echo "\"{$row['timestamp']}\", \"{$row['fromnode']}\", \"{$row['tonode']}\"\n";
     }
    }
   } else { // end of N_UUID string check
    echo "debug: Lair webserver: unknown packet \"$base64encoded\"\n";
   }
  } // end of other request type
 }
}

?>

