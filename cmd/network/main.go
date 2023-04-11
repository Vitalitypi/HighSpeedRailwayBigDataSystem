package main

import (
	"crypto/ecdsa"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"github.com/yonggewang/bdls"
	"github.com/yonggewang/bdls/global"
	"math/big"
	"os"
	"strconv"
)

func main4() {
	for i := 0; i < 10000; i++ {
		privateKey, err := ecdsa.GenerateKey(bdls.S256Curve, rand.Reader)
		global.MyError(err)
		r1, s1, err := ecdsa.Sign(rand.Reader, privateKey, []byte("hello,world"))
		global.MyError(err)
		sign := global.GetFillBytes(r1, s1)
		r := big.Int{}
		s := big.Int{}
		signLen := len(sign)
		r.SetBytes(sign[:(signLen / 2)])
		s.SetBytes(sign[(signLen / 2):])
		x := big.Int{}
		y := big.Int{}
		pubKey := global.GetPublicKey(privateKey.PublicKey)
		pubKeyLen := len(pubKey)
		x.SetBytes(pubKey[:(pubKeyLen / 2)])
		y.SetBytes(pubKey[(pubKeyLen / 2):])
		public := ecdsa.PublicKey{global.S256Curve, &x, &y}
		if !ecdsa.Verify(&public, []byte("hello,world"), &r, &s) {
			fmt.Println(ecdsa.Verify(&public, []byte("hello,world"), &r, &s))
			return
		}
	}
}
func main3() {
	dS := "36731978510278611428441252586301088430760792174628377080582195577034175321402"
	pubS := "57fdad390b91cbcaa6be4794cc836ba7f26aabad522659ad52b1d8dda6b87dae0dbc8cac90a4595103e9638aa7ab57f68fa1da4a33bd6ea1ca3a508ee56dd9"
	bts, err := hex.DecodeString(pubS)
	global.MyError(err)
	d := new(big.Int)
	d.SetString(dS, 10)
	x, y := bdls.S256Curve.ScalarBaseMult(d.Bytes())
	x_, y_ := new(big.Int), new(big.Int)
	mid := len(bts) / 2
	if len(bts)/2%2 == 1 {
		mid++
	}
	x_.SetBytes(bts[:mid])
	y_.SetBytes(bts[mid:])

	fmt.Println(x, y)
	fmt.Println(x_, y_)
}
func main() {
	//for i := 0; i < 4; i++ {
	//	des := fmt.Sprintf("./db/HSRBDS_%s.db", strconv.Itoa(5000+i*1000))
	//	fileIo(des)
	//}
	//生成数据库
	os.RemoveAll(global.DatabasePath)
	os.Mkdir(global.DatabasePath, os.ModePerm)
	//生成二级共识成员的数据库
	for i := 1; i <= global.NumGroup; i++ {
		for j := 0; j <= global.NumMember; j++ {
			des := fmt.Sprintf(global.DatabasePath+"\\HSRBDS_%s.db", strconv.Itoa(4000+i*1000+j*50))
			fileIo(des)
		}
	}

	//for i := 0; i < 4; i++ {
	//	port:=strconv.Itoa(5000+i*50)
	//	bc := global.GetBlockChain(port)
	//	bc.DB.Close()
	//}
	//bc := global.GetBlockChain("5050")
	//bc.DB.Close()
}

func fileIo(desPath string) {
	//创建一个新文件，写入内容 5 句 “http://c.biancheng.net/golang/”
	srcPath := global.GenesisPath
	src, err := os.OpenFile(srcPath, os.O_RDONLY|os.O_CREATE, 0666)
	if err != nil {
		fmt.Println("文件打开失败", err)
	}
	//及时关闭file句柄
	defer src.Close()
	des, _ := os.OpenFile(desPath, os.O_WRONLY|os.O_CREATE, 0666)
	defer des.Close()
	temp := make([]byte, 1024)
	for n, _ := src.Read(temp); n != 0; {
		des.Write(temp)
		n, _ = src.Read(temp)
	}
}

//x=34169884043478057197766693436970540090133271205477977118912571771799844303055
//y=51919755199586154349953104746301828530216889533883856298683155443585283156809
//d=57858738154638975994584785872386680755701967718753139577427421571050472380599
func main1() {
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
	admin, _ := hex.DecodeString(global.Admin[0])
	fmt.Println(admin)
	pubBytes := append(x.Bytes(), y.Bytes()...)
	pubStr := hex.EncodeToString(pubBytes)
	fmt.Println(pubStr)
}
