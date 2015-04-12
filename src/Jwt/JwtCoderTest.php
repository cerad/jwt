<?php

namespace Cerad\Component\Jwt;

use Cerad\Component\Jwt\JwtCoder;

require __DIR__  . '/../../vendor/autoload.php';

class JwtCoderTest extends \PHPUnit_Framework_TestCase
{
  public function testEncodeDecode()
  {
    $jwt = new JwtCoder('my_key');
    
    $msg = $jwt->encode('abc');
    
    $this->assertEquals($jwt->decode($msg), 'abc');
  }
  public function testValidToken()
  {
    $jwt = new JwtCoder('my_key');
    $payload = array(
      "message" => "abc",
       "exp" => time() + 20); // time in the future
    $encoded = $jwt->encode($payload);
    $decoded = $jwt->decode($encoded);
    $this->assertEquals($decoded['message'], 'abc');
  }
    public function testInvalidToken()
    {
      $jwt = new JwtCoder('my_key');
      $payload = array(
        "message" => "abc",
        "exp" => time() + 20); // time in the future
      $encoded = $jwt->encode($payload);
      $this->setExpectedException('UnexpectedValueException');
      $decoded = $jwt->decode($encoded, 'my_key2');
    }
}