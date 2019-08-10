<?php


class OpenPGP
{

    protected $input;

    const USER_ID_TAG = 13;

    function __construct($encodedInput)
    {
        $this->setInput($encodedInput);
    }

    /**
     * @return mixed
     */
    public function getInput()
    {
        return $this->input;
    }

    /**
     * @param mixed $input
     * @return OpenPGP
     */
    public function setInput($input)
    {
        $this->input = $input;
        return $this;
    }

    function parse()
    {
        $encodedInput = $this->unarmor();
        $userId = "";
        while (($length = strlen($encodedInput)) > 0) {
            if (($userId = $this->decode($encodedInput))) {
                //Found User Id string exit out
                break;
            }
            if ($length == strlen($encodedInput)) {
                //Reached the end of key, exit out
                break;
            }
        }
        return $userId;
    }


    function unarmor()
    {
        $asciiText = $this->getInput();
        $header = "-----BEGIN PGP PUBLIC KEY BLOCK-----";
        $asciiText = str_replace(["\r\n", "\r"], ["\n", ''], $asciiText);

        $headerPos = strpos($asciiText, $header);

        if ($headerPos === false) {
            return $headerPos;
        }

        $headerPos = strpos($asciiText, "\n\n", $headerPos + strlen($header));

        if ($headerPos !== false)
            $headerPos += 2;

        $footerPos = strpos($asciiText, "\n=", $headerPos);

        if ($headerPos && $footerPos)
            return base64_decode(substr($asciiText, $headerPos, $footerPos - $headerPos));

        return $headerPos && $footerPos;
    }

    function decode(&$encodedInput)
    {
        $packet = NULL;

        if (strlen($encodedInput) > 0) {
            list($tag, $headerLength, $dataLength) = ord($encodedInput[0]) & 64 ?
                $this->parseNewHeader($encodedInput) :
                $this->parseOldHeader($encodedInput);
            $encodedInput = substr($encodedInput, $headerLength);
            if ($tag == self::USER_ID_TAG) {
                return substr($encodedInput, 0, $dataLength);
            } else {
                $encodedInput = substr($encodedInput, $dataLength);
            }
        }
        return false;
    }


    function parseNewHeader($encodedInput)
    {
        $tag = ord($encodedInput[0]) & 63;
        $len = ord($encodedInput[1]);
        if ($len < 192) {
            return [$tag, 2, $len];
        }
        if ($len > 191 && $len < 224) {
            return [$tag, 3, (($len - 192) << 8) + ord($encodedInput[2]) + 192];
        }
        if ($len == 255) {
            return [$tag, 6, array_pop(unpack('N', substr($encodedInput, 2, 4)))];
        }
        return [];

    }

    function parseOldHeader($encodedInput)
    {
        $len = ($tag = ord($encodedInput[0])) & 3;
        $tag = ($tag >> 2) & 15;
        $headLength = 0;
        $dataLength = 0;
        switch ($len) {
            case 0:
                $headLength = 2;
                $dataLength = ord($encodedInput[1]);
                break;
            case 1:
                $headLength = 3;
                $dataLength = unpack('n', substr($encodedInput, 1, 2));
                $dataLength = $dataLength[1];
                break;
            case 2:
                $headLength = 5;
                $dataLength = unpack('N', substr($encodedInput, 1, 4));
                $dataLength = $dataLength[1];
                break;
            case 3:
                $headLength = 1;
                $dataLength = strlen($encodedInput) - $headLength;
                break;
        }
        return [$tag, $headLength, $dataLength];
    }

}


