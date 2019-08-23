<?php

class OpenPGP
{
    static function unarmor($text, $header = 'PGP PUBLIC KEY BLOCK')
    {
        $text = str_replace(array("\r\n", "\r"), array("\n", ''), $text);
        if (($pos1 = strpos($text, $header)) !== FALSE &&
            ($pos1 = strpos($text, "\n\n", $pos1 += strlen($header))) !== FALSE &&
            ($pos2 = strpos($text, "\n=", $pos1 += 2)) !== FALSE) {
            return base64_decode($text = substr($text, $pos1, $pos2 - $pos1));
        }
    }

}

class OpenPGP_Message
{
    public $packets = array();

    static function parse($input)
    {
        return self::parse_string($input);
    }


    static function parse_string($input)
    {
        $msg = [];
        while (($length = strlen($input)) > 0) {
            if (($packet = OpenPGP_Packet::parse($input))) {
                $msg[] = $packet;
            }
            if ($length == strlen($input)) { // is parsing stuck?
                break;
            }
        }
        return $msg;
    }

    function __construct(array $packets = array())
    {
        $this->packets = $packets;
    }

}

class OpenPGP_Packet
{
    public $data, $input;

    static function class_for($tag)
    {
        return isset(self::$tags[$tag]) && class_exists(
            $class = 'OpenPGP_' . self::$tags[$tag] . 'Packet') ? $class : __CLASS__;
    }


    static function parse(&$input)
    {
        $packet = NULL;
        if (strlen($input) > 0) {
            list($tag, $head_length, $data_length) = ord($input[0]) & 64 ? self::parse_new_format($input) : self::parse_old_format($input);
            $input = substr($input, $head_length);
            if (($tag == 13 || $tag == 2) && ($class = self::class_for($tag))) {
                /**
                 * @var $packet OpenPGP_UserIDPacket | OpenPGP_SignaturePacket
                 */
                $packet = new $class();
                $packet->input = substr($input, 0, $data_length);
                $packet->read();
                unset($packet->input);
            }
            $input = substr($input, $data_length);
        }
        return $packet;
    }


    static function parse_new_format($input)
    {
        $tag = ord($input[0]) & 63;
        $len = ord($input[1]);
        if ($len < 192) { // One octet length
            return array($tag, 2, $len);
        }
        if ($len > 191 && $len < 224) { // Two octet length
            return array($tag, 3, (($len - 192) << 8) + ord($input[2]) + 192);
        }
        if ($len == 255) { // Five octet length
            return array($tag, 6, array_pop(unpack('N', substr($input, 2, 4))));
        }
        return false;
    }


    static function parse_old_format($input)
    {
        $head_length = "";
        $data_length = '';
        $len = ($tag = ord($input[0])) & 3;
        $tag = ($tag >> 2) & 15;
        switch ($len) {
            case 0: // The packet has a one-octet length. The header is 2 octets long.
                $head_length = 2;
                $data_length = ord($input[1]);
                break;
            case 1: // The packet has a two-octet length. The header is 3 octets long.
                $head_length = 3;
                $data_length = unpack('n', substr($input, 1, 2));
                $data_length = $data_length[1];
                break;
            case 2: // The packet has a four-octet length. The header is 5 octets long.
                $head_length = 5;
                $data_length = unpack('N', substr($input, 1, 4));
                $data_length = $data_length[1];
                break;
            case 3: // The packet is of indeterminate length. The header is 1 octet long.
                $head_length = 1;
                $data_length = strlen($input) - $head_length;
                break;
        }
        return array($tag, $head_length, $data_length);
    }


    function read_unpacked($count, $format)
    {
        $unpacked = unpack($format, $this->read_bytes($count));
        return $unpacked[1];
    }

    function read_byte()
    {
        return ($bytes = $this->read_bytes()) ? $bytes[0] : NULL;
    }

    function read_bytes($count = 1)
    {
        $bytes = substr($this->input, 0, $count);
        $this->input = substr($this->input, $count);
        return $bytes;
    }

    static $tags = array(
        2 => 'Signature',                 // Signature Packet
        13 => 'UserID',                    // User ID Packet
    );
}


class OpenPGP_SignaturePacket extends OpenPGP_Packet
{
    public  $unhashed_subpackets;

    function read()
    {
        switch (ord($this->read_byte())) {
            case 3:
                // TODO: V3 sigs
                break;
            case 4:
                ord($this->read_byte());
                ord($this->read_byte());
                ord($this->read_byte());

                $hashed_size = $this->read_unpacked(2, 'n');
                $this->read_bytes($hashed_size);
                $unhashed_size = $this->read_unpacked(2, 'n');
                $this->unhashed_subpackets = self::get_subpackets($this->read_bytes($unhashed_size));

                $this->read_unpacked(2, 'n');
                break;
        }
    }


    static function get_subpackets($input)
    {
        $subpackets = array();
        while (($length = strlen($input)) > 0) {
            $subpackets[] = self::get_subpacket($input);
            if ($length == strlen($input)) { // Parsing stuck?
                break;
            }
        }
        return $subpackets;
    }

    static function get_subpacket(&$input)
    {
        $packet = '';
        $len = ord($input[0]);
        $length_of_length = 1;
        if ($len > 190 && $len < 255) { // Two octet length
            $length_of_length = 2;
            $len = (($len - 192) << 8) + ord($input[1]) + 192;
        }
        if ($len == 255) { // Five octet length
            $length_of_length = 5;
            $len = array_pop(unpack('N', substr($input, 1, 4)));
        }
        $input = substr($input, $length_of_length); // Chop off length header
        $tag = ord($input[0]);
        if ($tag == 16) {
            $packet = new OpenPGP_SignaturePacket_IssuerPacket();
            $packet->input = substr($input, 1, $len - 1);
            $packet->read();
            unset($packet->input);
        }
        $input = substr($input, $len); // Chop off the data from this packet
        return $packet;
    }

}


class OpenPGP_SignaturePacket_IssuerPacket extends OpenPGP_Packet
{
    function read()
    {
        for ($i = 0; $i < 8; $i++) { // Store KeyID in Hex
            $this->data .= sprintf('%02X', ord($this->read_byte()));
        }
    }
}

class OpenPGP_UserIDPacket extends OpenPGP_Packet
{
    function read()
    {
        $this->data = $this->input;
    }
}