<?php
    class myjwt{
        private $secret;
        public function __construct(string $secret){
            $this ->secret = $secret;
        }
        public function generate(string $alg,array $data){
            $header = $this->base64url_encode(json_encode(["alg"=>"HS256","typ"=>"JWT"]));
            $body = $this->base64url_encode(json_encode($data));
            $signature = $this->base64url_encode(hash_hmac($alg,$header.".".$body,$this->secret,true));
            return $header.".".$body.".".$signature;
        }
        public function validate(string $alg,string $token){
            list($header,$body,$signature) = explode(".",$token);
            $calculated_sig = hash_hmac($alg,$header.".".$body,$this->secret,true);
            if(hash_equals($calculated_sig,$this->base64url_decode($signature))){
                return "valid";
            }else{
                return "not valid";
            }
        }
        public function decode(string $alg,string $token){
            list($header,$body,$signature) = explode(".",$token);
            $header = $this->base64url_decode($header);
            $body = $this->base64url_decode($body);
            $signature = base64_decode($signature);
            return [$header,$body,$signature];
        }
        private function base64url_encode(string $str){
            $encoded = base64_encode($str);
            $encoded = strtr($encoded,"+/","-_");
            $encoded = rtrim($encoded,"=");
            return $encoded;
        }

        private function base64url_decode(string $encoded){
            $decoded = strtr($encoded,"-_","+/");
            $decoded = str_pad($decoded,strlen($encoded) % 4,"=",STR_PAD_RIGHT);
            return base64_decode($decoded);
        }
    }
