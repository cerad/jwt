<?php

namespace spec\Cerad\Component\Jwt;

use PhpSpec\ObjectBehavior;
use Prophecy\Argument;

class JwtCoderSpec extends ObjectBehavior
{
  function it_is_initializable()
  {
    $this->beConstructedWith('secret');
    $this->shouldHaveType('Cerad\Component\Jwt\JwtCoder');
  }
}
