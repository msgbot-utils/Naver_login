importClass(java.security.spec.RSAPublicKeySpec)
importClass(java.security.KeyFactory)
importClass(javax.crypto.Cipher)
importClass(org.jsoup.Jsoup)
importClass(java.util.UUID)
importClass(java.math.BigInteger)
importClass(java.lang.StringBuilder)
importClass(org.jsoup.Connection)

const createBvsd = require("./createBvsd")
const lzString = require("./lz-string.min")

module.exports = function naver_login(id, pw) {
    const dom = Jsoup.connect("https://nid.naver.com/nidlogin.login?svctype=262144").get()

    const dynamic = dom.select("#dynamicKey").get(0).attr("value")
    const keyString = dom.select("#session_keys").get(0).attr("value")

    const keys = keyString.split(",")
    const encnm = keys[1]
    const encpw = encrypt(keys, id, pw)
    const bvsd = makeBvsd(id)

    return Jsoup.connect("https://nid.naver.com/nidlogin.login")
      .data("localechange", "")
      .data("dynamicKey", dynamic)
      .data("encpw", encpw)
      .data("enctp", "1")
      .data("svctype", "262144")
      .data("smart_LEVEL", "-1")
      .data("bvsd", bvsd)
      .data("encnm", encnm)
      .data("locale", "ko_KR")
      .data("url", "https://m.naver.com")
      .data("id", "")
      .data("pw", "")
      .data("nvlong", "on")
      .method(Connection.Method.POST)
      .execute().cookies()
  };

  function encrypt(keys, id, pw) {
    const n = new BigInteger(keys[2], 16)
    const e = new BigInteger(keys[3], 16)

    const spec = new RSAPublicKeySpec(n, e)

    const factory = KeyFactory.getInstance("RSA")
    const key = factory.generatePublic(spec)

    const cipher = Cipher.getInstance("RSA/ECB/PKCS1Padding")
    cipher.init(Cipher.ENCRYPT_MODE, key)

    const plain = new java.lang.String(getLenChar(keys[0]) + keys[0] + getLenChar(id) + id + getLenChar(pw) + pw)

    const bytes = cipher.doFinal(plain.getBytes())
    return bytesToHex(bytes)
  }

  function getLenChar(str) {
    return String.fromCharCode(str.length)
  }

  function bytesToHex(bytes) {
    const builder = new StringBuilder()
    for (let b of bytes) {
      builder.append(java.lang.String.format("%02x", new java.lang.Byte(b)))
    }

    return builder.toString()
  }

  function makeBvsd(id) {
    const uuid = UUID.randomUUID() + "-0"
    const bvsd = createBvsd(uuid, id)

    return JSON.stringify({
      "uuid": uuid,
      "encData": lzString.compressToEncodedURIComponent(JSON.stringify(bvsd))
    })
  }
