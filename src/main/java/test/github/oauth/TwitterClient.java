package test.github.oauth;

import io.micronaut.core.io.buffer.ByteBuffer;
import io.micronaut.http.MediaType;
import io.micronaut.http.annotation.Body;
import io.micronaut.http.annotation.Get;
import io.micronaut.http.annotation.Header;
import io.micronaut.http.annotation.Post;
import io.micronaut.http.client.annotation.Client;
import io.reactivex.Single;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import java.io.UnsupportedEncodingException;
import java.net.URLDecoder;
import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.security.Key;
import java.time.Instant;
import java.util.*;
import java.util.stream.Collectors;

@Header(name = "User-Agent", value = "Micronaut")
@Client("https://api.twitter.com")
public abstract class TwitterClient {

    private static final String CONSUMER_KEY = "____YOUR-TWITTER-CONSUMER-KEY____";
    private static final String CONSUMER_SECRET = "____YOUR-TWITTER-CONSUMER_SECRET____";
    private static final String SIGNATURE_METHOD = "HMAC-SHA1";
    private static final String VERSION = "1.0";
    private static final String HMAC_SHA1_ALGORITHM = "HmacSHA1";
    private static final String PARAM_KEY = "oauth_consumer_key";
    private static final String PARAM_NONCE = "oauth_nonce";
    private static final String PARAM_SIG_METHOD = "oauth_signature_method";
    private static final String PARAM_TIMESTAMP = "oauth_timestamp";
    private static final String PARAM_VERSION = "oauth_version";
    private static final String PARAM_TOKEN = "oauth_token";
    private static final String PARAM_SIG = "oauth_signature";
    private static final String PARAM_VERIFIER = "oauth_verifier";
    private static final String PARAM_CALLBACK = "oauth_callback";


    @Post(uri = "/oauth/request_token", consumes = MediaType.TEXT_HTML)
    abstract Single<ByteBuffer> _requestToken(@Header("Authorization") String authorization);

    public Single<Map<String, String>> requestToken(String callbackUrl) {
        Map<String, String> additionalParams = Collections.singletonMap(PARAM_CALLBACK, callbackUrl);

        return _requestToken(getAuthorizationHeader("POST", "/oauth/request_token", null, null, additionalParams)).map(this::convertTwitterResponse);
    }

    @Post(uri = "/oauth/access_token", consumes = MediaType.TEXT_HTML, produces = MediaType.APPLICATION_FORM_URLENCODED)
    abstract Single<ByteBuffer> _accessToken(@Header("Authorization") String authorization, @Body Map<String,String> body);

    public Single<Map<String, String>> accessToken(String token, String verifier) {
        Map<String, String> body = new HashMap<>(1);
        body.put(PARAM_VERIFIER, verifier);

        return _accessToken(getAuthorizationHeader("POST","/oauth/access_token", token, token, Collections.emptyMap()), body).map(this::convertTwitterResponse);
    }

    @Get(value = "/1.1/account/verify_credentials.json")
    abstract Single<Map<String, Object>> _userInfo(@Header("Authorization") String authorization);

    public Single<Map<String, Object>> userInfo(String token, String secret) {
        return _userInfo(getAuthorizationHeader("GET","/1.1/account/verify_credentials.json", token, secret, Collections.emptyMap()));
    }

    private String getAuthorizationHeader(String method, String path, String token, String secret, Map<String, String> addlParams) {
        Map<String, String> tokenParameters = new TreeMap<>(addlParams);

        tokenParameters.put(PARAM_KEY, CONSUMER_KEY);
        tokenParameters.put(PARAM_NONCE, UUID.randomUUID().toString());
        tokenParameters.put(PARAM_SIG_METHOD, SIGNATURE_METHOD);
        tokenParameters.put(PARAM_TIMESTAMP, String.valueOf(Instant.now().getEpochSecond()));
        tokenParameters.put(PARAM_VERSION, VERSION);

        String signingKey = encode(CONSUMER_SECRET) + "&";

        if (secret != null) {
            signingKey = signingKey + encode(secret);
        }

        if (token != null) {
            tokenParameters.put(PARAM_TOKEN, token);
        }

        String signParams = tokenParameters.entrySet().stream().map(entry -> {
            return encode(entry.getKey()) + "=" + encode(entry.getValue());
        }).reduce((a, b) -> a + "&" + b)
                .map(params -> {
                    return method.toUpperCase() + "&" + encode("https://api.twitter.com" + path) + "&" + encode(params);
                }).get();

        tokenParameters.put(PARAM_SIG, sign(signingKey, signParams));

        return "OAuth " + tokenParameters.entrySet().stream()
                .map(entry ->
                        encode(entry.getKey()) + "=\"" + encode(entry.getValue()) + "\"")
                .reduce((a, b) -> a + "," + b)
                .orElse("");
    }

    private String encode(String value) {
        try {
            return URLEncoder.encode(value, StandardCharsets.UTF_8.name());
        } catch (UnsupportedEncodingException e) {
            return null;
        }
    }

    private String sign(String key, String value) {
        String result = null;

        try {
            Key signingKey = new SecretKeySpec(key.getBytes(), HMAC_SHA1_ALGORITHM);
            Mac mac = Mac.getInstance(HMAC_SHA1_ALGORITHM);
            mac.init(signingKey);
            byte[] rawHmac = mac.doFinal(value.getBytes());
            result = Base64.getEncoder().encodeToString(rawHmac);
        } catch (Exception ignored) { }

        return result;
    }

    private Map<String, String> convertTwitterResponse(ByteBuffer buffer) {
        return Arrays.stream(buffer.toString(StandardCharsets.UTF_8).split("&"))
                .map(keyValue -> {
                    String[] parts = keyValue.split("=");
                    try {
                        String key = URLDecoder.decode(parts[0], StandardCharsets.UTF_8.name());
                        String value = URLDecoder.decode(parts[1], StandardCharsets.UTF_8.name());
                        return new AbstractMap.SimpleEntry<>(key, value);
                    } catch (UnsupportedEncodingException ignored) {
                        return null;
                    }
                })
                .collect(Collectors.toMap(Map.Entry::getKey, Map.Entry::getValue));
    }
}
