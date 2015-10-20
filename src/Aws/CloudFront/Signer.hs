{-# LANGUAGE CPP, RecordWildCards            #-}

module Aws.CloudFront.Signer
    ( URL
    , JSONPOlicy
    , CloudFrontSigningKey(..)
    , CloudFrontPolicy(..)
    , readCloudFrontSigningKeyFromDER
    , parseRSAPrivateKeyDER
    , signCannedPolicyURL
    , signCustomPolicyURL
    , signCustomPolicyURL_
    , cannedPolicy
    , customPolicy
    , unixTime
    ) where

import qualified Data.ASN1.Encoding             as A
import qualified Data.ASN1.BinaryEncoding       as A
import qualified Data.ASN1.Types                as A
import qualified Data.ByteString.Lazy.Char8     as LBS
import qualified Data.ByteString.Base64.Lazy    as B64
import           Data.Time
import           Data.Maybe
import           Codec.Crypto.RSA
import qualified Crypto.Types.PubKey.RSA        as C
import           Text.Printf
#if MIN_VERSION_time(1,5,0)
#else
import           System.Locale (defaultTimeLocale)
#endif

-- | input and output URLs
type URL        = String

-- | a JSON CloudFront policy
type JSONPOlicy = String        

-- | the CloudFront key pair identifier
type KeyID      = String        


-- | a CloudFront siging key has an identifier and an RSA private key

data CloudFrontSigningKey
    = CloudFrontSigningKey
        { cfk_key_id :: KeyID
        , cfk_key    :: PrivateKey
        }
    deriving (Show)

-- | a CloudFront policy must identify the resource being accessed and the
--   expiry time; a starting time and IPv4 address may also be specified

data CloudFrontPolicy
    = CloudFrontPolicy
        { cfp_Resource        :: URL
        , cfp_DateLessThan    :: UTCTime
        , cfp_DateGreaterThan :: Maybe UTCTime
        , cfp_IpAddress       :: Maybe String
        }

-- | RSA private keys can only be read from DER file for now (the OpenSSL
--   tools can be used to convert from PEM:
--
--      openssl rsa -in input.pem -inform PEM -out output.der -outform DER
--

readCloudFrontSigningKeyFromDER :: KeyID -> FilePath -> IO CloudFrontSigningKey
readCloudFrontSigningKeyFromDER ki fp = 
 do pk_b <- LBS.readFile fp
    case parseRSAPrivateKeyDER pk_b of
      Left err -> error err
      Right pk ->
        return $
            CloudFrontSigningKey 
                { cfk_key_id = ki
                , cfk_key    = pk
                }

-- | If you have the DER ByteString then you can construct a private key
--   functionally.

parseRSAPrivateKeyDER :: LBS.ByteString -> Either String C.PrivateKey
parseRSAPrivateKeyDER bs = 
    case A.decodeASN1 A.DER bs of
      Left err -> Left $ show err
      Right as ->
        case A.fromASN1 as of
          Left err -> Left $ show err
          Right pr -> 
            case pr of
              (pk,[]) -> Right pk
              _       -> Left "residula data"

-- | In most cases only a time-limited, signed URL is needed, in which case a
--   canned policy can be used; URLs signed with a canned policy are shorter
--   than those signed with a custom policy.

signCannedPolicyURL :: CloudFrontSigningKey -> UTCTime -> URL -> URL
signCannedPolicyURL CloudFrontSigningKey{..} exp_utc url = 
    printf "%s%cExpires=%s&Signature=%s&Key-Pair-Id=%s" url sep exp_eps pol_sig cfk_key_id  
  where
    exp_eps = unixTime exp_utc
    pol_sig = b64 $ rsa_sha1 cfk_key pol 
    pol     = cannedPolicy exp_utc url
    sep     = if any (=='?') url then '&' else '?'

-- | Signing a URL with a custom policy allows a start time to be specified and
--   the IP address of the recipient(s) to be specified.

signCustomPolicyURL :: CloudFrontSigningKey -> CloudFrontPolicy -> URL
signCustomPolicyURL cfk cfp = signCustomPolicyURL_ cfk (customPolicy cfp) $ cfp_Resource cfp

-- | The URL can also be signed with the custom policy in JSON format.
--   (See the CloudFront documentation for details.)

signCustomPolicyURL_ :: CloudFrontSigningKey -> JSONPOlicy -> URL -> URL
signCustomPolicyURL_ CloudFrontSigningKey{..} pol url =
    printf "%s%cPolicy=%s&Signature=%s&Key-Pair-Id=%s" url sep pol_b64 pol_sig cfk_key_id  
  where
    pol_sig = b64 $ rsa_sha1 cfk_key pol 
    pol_b64 = b64            pol
    sep     = if any (=='?') url then '&' else '?'

-- | The JSON canned policy can be generated from the expiry time and
--   the URL of the distributed resource.

cannedPolicy :: UTCTime -> URL -> JSONPOlicy
cannedPolicy exp_utc url =
    concat
        [ "{\"Statement\":[{\"Resource\":\""
        , url    
        , "\",\"Condition\":{\"DateLessThan\":{\"AWS:EpochTime\":"
        , unixTime exp_utc
        , "}}}]}"
        ]

-- | JSON custom policies provide more flexibility (allowing start times and
--   recipient IP addresses to be specified) but generate longer signed URLs.

customPolicy :: CloudFrontPolicy -> JSONPOlicy
customPolicy CloudFrontPolicy{..} = unlines $ catMaybes
    [ ok $          "{"
    , ok $          "   \"Statement\": [{"
    , ok $          "      \"Resource\":\""                             ++                      cfp_Resource     ++ "\","
    , ok $          "      \"Condition\":{"
    , ok $          "         \"DateLessThan\":{\"AWS:EpochTime\":"     ++ unixTime             cfp_DateLessThan ++ "},"
    , st $ \ust ->  "         \"DateGreaterThan\":{\"AWS:EpochTime\":"  ++ unixTime             ust              ++ "},"
    , ok $          "         \"IpAddress\":{\"AWS:SourceIp\":\""       ++ maybe "0.0.0.0/0" id cfp_IpAddress    ++"\"}"
    , ok $          "      }"
    , ok $          "   }]"
    , ok $          "}"
    ]
  where
    ok   = Just
    st f = maybe Nothing (Just . f) cfp_DateGreaterThan

-- | CloudFront uses Unix Epoch time (number of seconds since 1970, UTC) to
--   specify UTC.

unixTime :: UTCTime -> String
unixTime = formatTime defaultTimeLocale "%s" 

ha_sha1 :: HashInfo
#if MIN_VERSION_RSA(2,0,0)
ha_sha1 = hashSHA1
#else
ha_sha1 = ha_SHA1
#endif

rsa_sha1 :: PrivateKey -> String -> String
rsa_sha1 pk = LBS.unpack . rsassa_pkcs1_v1_5_sign ha_sha1 pk . LBS.pack

b64 :: String -> String
b64 = map f . LBS.unpack . B64.encode . LBS.pack
  where
    f '+' = '-'
    f '=' = '_'
    f '/' = '~'
    f c   = c
