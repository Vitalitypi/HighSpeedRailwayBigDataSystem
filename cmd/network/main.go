package main

import (
	"crypto/ecdsa"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"github.com/gin-gonic/gin"
	"github.com/yonggewang/bdls"
	"github.com/yonggewang/bdls/blockchain/common"
	"github.com/yonggewang/bdls/global"
	"math/big"
	"net/http"
)

func RunHttpServer() {
	// 1.创建路由
	r := gin.Default()
	// 2.绑定路由规则，执行的函数
	// gin.Context，封装了request和response
	r.GET("/", func(c *gin.Context) {
		c.String(http.StatusOK, "hello World!")
	})
	r.POST("/register", func(c *gin.Context) {
		fmt.Println(c.PostForm("name"))
		c.JSON(http.StatusOK, gin.H{
			"status": gin.H{
				"code":    http.StatusOK,
				"success": true,
			},
			"name": "Jane",
			"nick": "123",
		})
	})
	// 3.监听端口，默认在8080
	// Run("里面不指定端口号默认为8080")
	r.Run(":8000")
}

//x=34169884043478057197766693436970540090133271205477977118912571771799844303055
//y=51919755199586154349953104746301828530216889533883856298683155443585283156809
//d=57858738154638975994584785872386680755701967718753139577427421571050472380599
func main() {
	privateKey, err := ecdsa.GenerateKey(bdls.S256Curve, rand.Reader)
	global.MyError(err)
	//var d *big.Int = 87585985519223974488853297907837996030399358105161758328314184249385229751691
	fmt.Println(privateKey.X, privateKey.Y, privateKey.D)
	var pub = ecdsa.PublicKey{bdls.S256Curve, privateKey.X, privateKey.Y}
	var priv = &ecdsa.PrivateKey{pub, privateKey.D}
	fmt.Println(bdls.S256Curve.ScalarBaseMult(privateKey.D.Bytes()))
	priv.PublicKey.X, priv.PublicKey.Y = bdls.S256Curve.ScalarBaseMult(priv.D.Bytes())

	priStr := "2eff810301010a507269766174654b657901ff8200010201095075626c69634b657901ff840001014401ff860000002fff83030101095075626c69634b657901ff840001030105437572766501100001015801ff860001015901ff860000000aff85050102ff8800000046ff8201011963727970746f2f656c6c69707469632e703235364375727665ff890301010970323536437572766501ff8a000101010b4375727665506172616d7301ff8c00000053ff8b0301010b4375727665506172616d7301ff8c00010701015001ff860001014e01ff860001014201ff86000102477801ff86000102477901ff8600010742697453697a6501040001044e616d65010c000000fe012cff8affbd01012102ffffffff00000001000000000000000000000000ffffffffffffffffffffffff012102ffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc6325510121025ac635d8aa3a93e7b3ebbd55769886bc651d06b0cc53b0f63bce3c3e27d2604b0121026b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c2960121024fe342e2fe1a7f9b8ee7eb4a7c0f9e162bce33576b315ececbb6406837bf51f501fe02000105502d323536000001210273ccd17cdc6275381f365f14e24ccae8e95a216d399889ff793a7a59e134795c012102e7270a9009b11b250235d314499f2258d9c8952a298bc2d5b09ae80c821f676d00012102fe8e63a919332baa17c60530a70cd3fbe505848e2d26ffc23ae3e1bb138db5c900"
	pri_admin := global.BackPrivate(priStr)
	fmt.Println(pri_admin.D.String())
	n := new(big.Int)
	n, _ = n.SetString("115139043655121369876744144402956672223889454523067809828600815499456893793737", 10)
	fmt.Println(n.SetBytes(n.Bytes()))
	x, y := bdls.S256Curve.ScalarBaseMult(n.Bytes())
	admin, _ := hex.DecodeString(global.Admin)
	fmt.Println(admin)
	pubBytes := append(x.Bytes(), y.Bytes()...)
	pubStr := hex.EncodeToString(pubBytes)
	fmt.Println(pubStr)
}
func Register() {
	//管理员公钥字符串
	priStr := "2eff810301010a507269766174654b657901ff8200010201095075626c69634b657901ff840001014401ff860000002fff83030101095075626c69634b657901ff840001030105437572766501100001015801ff860001015901ff860000000aff85050102ff8800000046ff8201011963727970746f2f656c6c69707469632e703235364375727665ff890301010970323536437572766501ff8a000101010b4375727665506172616d7301ff8c00000053ff8b0301010b4375727665506172616d7301ff8c00010701015001ff860001014e01ff860001014201ff86000102477801ff86000102477901ff8600010742697453697a6501040001044e616d65010c000000fe012cff8affbd01012102ffffffff00000001000000000000000000000000ffffffffffffffffffffffff012102ffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc6325510121025ac635d8aa3a93e7b3ebbd55769886bc651d06b0cc53b0f63bce3c3e27d2604b0121026b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c2960121024fe342e2fe1a7f9b8ee7eb4a7c0f9e162bce33576b315ececbb6406837bf51f501fe02000105502d323536000001210273ccd17cdc6275381f365f14e24ccae8e95a216d399889ff793a7a59e134795c012102e7270a9009b11b250235d314499f2258d9c8952a298bc2d5b09ae80c821f676d00012102fe8e63a919332baa17c60530a70cd3fbe505848e2d26ffc23ae3e1bb138db5c900"
	pubStr := global.Admin
	pub_admin, _ := hex.DecodeString(pubStr)
	pri_admin := global.BackPrivate(priStr)
	//生成公私钥对
	_, pub := global.NewKeyPair()
	//生成用户信息	生成的公钥作为账户存储到区块链，用登录的账户来作为公钥进行签名
	infoUser := common.InfoUser{nil, pub_admin, nil, pub, []byte("test")}
	infoUser.Sign(pri_admin)
	infoUser.Hash = infoUser.HashInfoUser()
	fmt.Println(infoUser.Verify())
}
