package cryptopals

import (
	"bytes"
	"crypto/aes"
	"encoding/base64"
	mathrand "math/rand"
	"os"
	"strings"
	"testing"
	"time"
)

func decodeBase64(t *testing.T, b64Text string) []byte {
	text, err := base64.StdEncoding.DecodeString(b64Text)
	if err != nil {
		t.Errorf("Error: %s", err)
	}
	return text
}

func readFile(t *testing.T, filename string) []byte {
	text, err := os.ReadFile(filename)
	if err != nil {
		t.Errorf("Error: %s", err)
	}
	return text
}

func TestNewCBCPaddingOracles(t *testing.T) {

	plaintexts := [][]byte{
		decodeBase64(t, "MDAwMDAwTm93IHRoYXQgdGhlIHBhcnR5IGlzIGp1bXBpbmc="),
		decodeBase64(t, "MDAwMDAxV2l0aCB0aGUgYmFzcyBraWNrZWQgaW4gYW5kIHRoZSBWZWdhJ3MgYXJlIHB1bXBpbic="),
		decodeBase64(t, "MDAwMDAyUXVpY2sgdG8gdGhlIHBvaW50LCB0byB0aGUgcG9pbnQsIG5vIGZha2luZw=="),
		decodeBase64(t, "MDAwMDAzQ29va2luZyBNQydzIGxpa2UgYSBwb3VuZCBvZiBiYWNvbg=="),
		decodeBase64(t, "MDAwMDA0QnVybmluZyAnZW0sIGlmIHlvdSBhaW4ndCBxdWljayBhbmQgbmltYmxl"),
		decodeBase64(t, "MDAwMDA1SSBnbyBjcmF6eSB3aGVuIEkgaGVhciBhIGN5bWJhbA=="),
		decodeBase64(t, "MDAwMDA2QW5kIGEgaGlnaCBoYXQgd2l0aCBhIHNvdXBlZCB1cCB0ZW1wbw=="),
		decodeBase64(t, "MDAwMDA3SSdtIG9uIGEgcm9sbCwgaXQncyB0aW1lIHRvIGdvIHNvbG8="),
		decodeBase64(t, "MDAwMDA4b2xsaW4nIGluIG15IGZpdmUgcG9pbnQgb2g="),
		decodeBase64(t, "MDAwMDA5aXRoIG15IHJhZy10b3AgZG93biBzbyBteSBoYWlyIGNhbiBibG93"),
	}

	for _, plaintext := range plaintexts {
		encryptMessage, checkMessagePadding := NewCBCPaddingOracles(plaintext)

		res := AttackCBCPaddingOracle(encryptMessage(), checkMessagePadding)
		t.Logf("-> %q", res)

		if !bytes.Equal(res, plaintext) {
			t.Errorf("Plaintext %q recovered incorrectly from %q", res, plaintext)
		}
	}

}

func TestDecryptCTR(t *testing.T) {
	b64Text := "L77na/nrFsKvynd6HzOoG7GHTLXsTVu9qvY/2syLXzhPweyyMTJULu/6/kXX0KSvoOLSFQ=="
	nonce := make([]byte, 8)
	key := []byte("YELLOW SUBMARINE")
	cipher, err := aes.NewCipher(key)
	if err != nil {
		t.Errorf("Error: %s", err)
	}

	msg := decodeBase64(t, b64Text)
	res := DecryptCTR(msg, cipher, nonce)
	t.Logf("%q", res)
	if len(res) != len(msg) {
		t.Error("Wrong length.")
	}
}

func TestBreakFixedNonceCTR(t *testing.T) {
	encryptMessage := NewFixedNonceCTROracle()
	var plainTexts, cipherTexts [][]byte

	b64Text := readFile(t, "testdata/20.txt")
	for _, line := range strings.Split(string(b64Text), "\n") {
		pt := decodeBase64(t, line)
		plainTexts = append(plainTexts, pt)
		cipherTexts = append(cipherTexts, encryptMessage(pt))
	}

	keystream := FindFixedNonceCTRKeystream(cipherTexts)

	for i := range plainTexts {
		t.Logf("%d: %q", i, XOR(keystream, cipherTexts[i]))
	}
}

var MT19937TestVector = []uint32{
	1791095845, 4282876139, 3093770124, 4005303368, 491263, 550290313,
	1298508491, 4290846341, 630311759, 1013994432, 396591248, 1703301249,
	799981516, 1666063943, 1484172013, 2876537340, 1704103302, 4018109721,
	2314200242, 3634877716, 1800426750, 1345499493, 2942995346, 2252917204,
	878115723, 1904615676, 3771485674, 986026652, 117628829, 2295290254,
	2879636018, 3925436996, 1792310487, 1963679703, 2399554537, 1849836273,
	602957303, 4033523166, 850839392, 3343156310, 3439171725, 3075069929,
	4158651785, 3447817223, 1346146623, 398576445, 2973502998, 2225448249,
	3764062721, 3715233664, 3842306364, 3561158865, 365262088, 3563119320,
	167739021, 1172740723, 729416111, 254447594, 3771593337, 2879896008,
	422396446, 2547196999, 1808643459, 2884732358, 4114104213, 1768615473,
	2289927481, 848474627, 2971589572, 1243949848, 1355129329, 610401323,
	2948499020, 3364310042, 3584689972, 1771840848, 78547565, 146764659,
	3221845289, 2680188370, 4247126031, 2837408832, 3213347012, 1282027545,
	1204497775, 1916133090, 3389928919, 954017671, 443352346, 315096729,
	1923688040, 2015364118, 3902387977, 413056707, 1261063143, 3879945342,
	1235985687, 513207677, 558468452, 2253996187, 83180453, 359158073,
	2915576403, 3937889446, 908935816, 3910346016, 1140514210, 1283895050,
	2111290647, 2509932175, 229190383, 2430573655, 2465816345, 2636844999,
	630194419, 4108289372, 2531048010, 1120896190, 3005439278, 992203680,
	439523032, 2291143831, 1778356919, 4079953217, 2982425969, 2117674829,
	1778886403, 2321861504, 214548472, 3287733501, 2301657549, 194758406,
	2850976308, 601149909, 2211431878, 3403347458, 4057003596, 127995867,
	2519234709, 3792995019, 3880081671, 2322667597, 590449352, 1924060235,
	598187340, 3831694379, 3467719188, 1621712414, 1708008996, 2312516455,
	710190855, 2801602349, 3983619012, 1551604281, 1493642992, 2452463100,
	3224713426, 2739486816, 3118137613, 542518282, 3793770775, 2964406140,
	2678651729, 2782062471, 3225273209, 1520156824, 1498506954, 3278061020,
	1159331476, 1531292064, 3847801996, 3233201345, 1838637662, 3785334332,
	4143956457, 50118808, 2849459538, 2139362163, 2670162785, 316934274,
	492830188, 3379930844, 4078025319, 275167074, 1932357898, 1526046390,
	2484164448, 4045158889, 1752934226, 1631242710, 1018023110, 3276716738,
	3879985479, 3313975271, 2463934640, 1294333494, 12327951, 3318889349,
	2650617233, 656828586, 1402929172, 2485213814, 2263697328, 38689046,
	3805092325, 3045314445, 1534461937, 2021386866, 3902128737, 3283900085,
	2677311316, 2007436298, 67951712, 1155350711, 3991902525, 3572092472,
	2967379673, 2367922581, 4283469031, 300997728, 740196857, 2029264851,
	588993561, 3190150641, 4005467022, 824445069, 2992811220, 1994202740,
	283468587, 989400710, 3244689101, 2182906552, 3237873595, 895794063,
	3964360216, 211760123, 3055975561, 2228494786, 533739719, 739929909,
	85384517, 1702152612, 112575333, 461130488, 121575445, 2189618472,
	1057468493, 438667483, 3693791921, 1240033649, 2314261807, 995395021,
	2374352296, 4156102094, 3616495149, 1195370327, 533320336, 1003401116,
	1199084778, 393231917, 2515816899, 2448417652, 4164382018, 1794980814,
	2409606446, 1579874688, 80089501, 3491786815, 3438691147, 1244509731,
	1000616885, 3081173469, 3466490401, 2632592002, 1665848788, 1833563731,
	3708884016, 3229269814, 3208863008, 1837441277, 2389033628, 1839888439,
	586070738, 1554367775, 257344540, 658583774, 521166154, 4025201800,
	191348845, 3935950435, 461683744, 3358486024, 969414228, 2647112653,
	3062264370, 154616399, 2403966121, 2810299200, 53927532, 557356243,
	309127192, 1264264305, 4154420202, 1549687572, 2439972908, 1179591951,
	873137822, 317694427, 1083730830, 653424115, 3194707731, 694146299,
	839363226, 4031736043, 2496917590, 1594007943, 4166204131, 214826037,
	3637101999, 3182379886, 1030138300, 1282821875, 2120724770, 877711460,
	2662689508, 4216612640, 3560445843, 3835496899, 673413912, 3261378259,
	79784165, 2796541534, 300742822, 170439343, 2088836327, 3495572357,
	2604165199, 3275226687, 2443198321, 1955423319, 1363061152, 2284177194,
	4246074058, 469594818, 2489986776, 627205858, 1632693918, 2185230993,
	2366304580, 926210880, 3201187004, 3936095732, 2874333390, 1984929937,
	1137820839, 568083619, 284905937, 3282392732, 1589499542, 913684262,
	2704616105, 318937546, 902690509, 409822534, 3233060505, 696667366,
	285772016, 1530999856, 1118044850, 409343934, 3456394540, 615309929,
	830793910, 3998670080, 2746463574, 2476410359, 2253441808, 3606248723,
	3972019977, 2677019248, 1130851036, 1393792051, 283300719, 3126786186,
	3157084283, 2245136708, 3316479383, 3164581134, 3899039423, 710413845,
	4002789550, 2950892924, 59921539, 1833138616, 1006577496, 3129130192,
	2649042862, 3248435766, 4075994063, 1707727431, 4080975356, 3973704206,
	2390807245, 874070159, 3932499353, 34371381, 2755505876, 3978646009,
	1675070394, 1264917461, 2087314034, 717051630, 2595493789, 103515692,
	2360290341, 1941332118, 3977918939, 3471788470, 3945930060, 1582166540,
	1695977848, 2616524091, 4137181082, 149669836, 747133895, 1522897623,
	542581159, 337240701, 580160555, 2977207756, 2171802482, 54600486, 92448347,
	1973731952, 4071501053, 4128826181, 3552433890, 1435314593, 64506027,
	2027582874, 756757176, 452651973, 1426202185, 2160694580, 562627161,
	3804008987, 3476736043, 2295133185, 1480632658, 1208933503, 4037730910,
	1522929632, 2499731866, 3849494356, 3774554654, 1037187943, 3628106816,
	102581398, 3888630370, 4147765044, 1975170691, 1846698054, 2346541708,
	1487297831, 3429976294, 2478486611, 1227153135, 543425712, 2105622845,
	4080404934, 2573159181, 1346948260, 66714903, 4092378518, 2548983234,
	937991802, 1862625756, 1068159225, 3467587050, 3710000479, 1353966133,
	1010469769, 3834927785, 3500828089, 2481877848, 2336020845, 790317814,
	821456605, 3384130292, 2529048268, 2628653906, 206745962, 231538571,
	68173929, 1804718116, 213507184, 2916578448, 1715475614, 3945364595,
	2477783658, 1726676, 3725959097, 4195148579, 3376541097, 1617400145,
	1093939970, 4182368469, 353282141, 2597235876, 677556845, 3559865646,
	899765072, 2468367131, 1792645448, 2697566748, 1493317250, 1226540771,
	3005979021, 2520429993, 2995780473, 3221318948, 320936676, 3686429864,
	156636178, 3243053281, 3390446502, 2998133055, 3867740659, 3712910894,
	20028776, 1385904345, 1134744551, 2881015920, 2007370239, 1936488805,
	1545398786, 1641118818, 1031726876, 1764421326, 99508939, 1724341690,
	2283497130, 1363153690, 559182056, 2671123349, 2411447866, 1847897983,
	720827792, 4182448092, 1808502309, 2911132649, 2940712173, 852851176,
	1176392938, 1832666891, 42948502, 1474660870, 944318560, 3425832590,
	137250916, 3779563863, 4015245515, 3881971619, 3359059647, 2846359931,
	2223049248, 1160535662, 70707035, 1083906737, 1283337190, 3671758714,
	2322372736, 2266517142, 3693171809, 3445255622, 795059876, 2458819474,
	358828827, 3148823196, 190148069, 2229137972, 1906140774, 3310921202,
	82973406, 2443226489, 287900466, 2000208686, 3486532103, 1471837653,
	2732847376, 292956903, 3319367325, 1623171979, 3030881725, 341991419,
	1023108090, 4221167374, 190773608, 780021278, 1207817352, 3486906536,
	3715531696, 3757931678, 314062231, 2956712386, 2836103900, 2445959872,
	804784871, 691367052, 2243203729, 2005234426, 3882131873, 1482502666,
	2040765468, 966539241, 3637933003, 2544819077, 3602530129, 1341188741,
	598203257, 3935502378, 2320590422, 3906854836, 2006116153, 1104314680,
	939235918, 476274519, 1893343226, 828768629, 2062779089, 2145697674,
	1431445192, 3129251632, 38279669, 894188307, 2170951052, 1065296025,
	2891145549, 3657902864, 238195972, 1786056664, 676799350, 2648642203,
	2598898610, 1003588420, 1371055747, 437946042, 3824741900, 2215588994,
	3394628428, 2049304928, 934152032, 655719741, 859891087, 2670637412,
	2922467834, 2336505674, 670946188, 2809498514, 2191983774, 620818363,
	4243705477, 3227787408, 621447007, 953693792, 207446972, 2230599083,
	3861450476, 3372820767, 3072317163, 95908451, 1332847916, 1393126168,
	1687665598, 3749173071, 346963477, 3628000147, 1512349517, 2312584737,
	4352004, 3722054183, 2682767484, 4079385667, 860159138, 3549391010,
	2684833834, 3668397902, 1380625106, 424099686, 203230246, 2797330810,
	3106827952, 3021582458, 3260962513, 2620964350, 1745063685, 3434321402,
	3025095910, 148482267, 2514098677, 3308150152, 4164247848, 3142750405,
	1305147909, 1115396103, 1347569102, 1104104229, 972645225, 2715722062,
	2887654945, 1483041307, 3345445555, 3421322317, 2201865246, 1916183467,
	2642542766, 3361883145, 196113219, 4254043907, 1915982787, 1289556790,
	4157582689, 614205375, 1544299747, 3871090256, 2379549980, 2325979813,
	1766753728, 4186477989, 4149138397, 2734195090, 872126798, 4268823911,
	4264157638, 2345356252, 2831242292, 2260982154, 3474960288, 581658414,
	1967743039, 1527742075, 3810959069, 112607890, 2293230500, 688892061,
	2479396344, 3202487335, 3940625180, 130565686, 1349249053, 1574290615,
	3118740839, 3703748954, 3458461595, 2975028156, 2061854570, 2967573900,
	2094115985, 810188871, 3613828699, 1897964423, 2385972604, 2497855955,
	1159131320, 4250951219, 2090544032, 875770572, 1184749118, 1064004710,
	968044723, 1126024800, 2777786910, 3221965974, 3956238597, 1962694107,
	861032543, 244510057, 3778940310, 2184060620, 2000628852, 910361965,
	3113765910, 3429979110, 1300822418, 1277028573, 2100270365, 118566930,
	874774580, 2548772986, 380603935, 3624267057, 711631586, 1636451795,
	2160353657, 3220616925, 3382634669, 2195335915, 3880940467, 2323370326,
	942848783, 4120739015, 3170248368, 3452985756, 1107254995, 138826523,
	2423258109, 3046795051, 568780947, 1997166159, 1598104390, 4069691736,
	355861498, 951046358, 2172077579, 1147065573, 2982454721, 349928029,
	1962705167, 1840903859, 1551663074, 468232022, 3504725549, 2722093427,
	196758975, 3448700842, 1665707670, 2992735341, 1969342055, 3290852818,
	3159945384, 1470829228, 3906860944, 3632904465, 1191447403, 1841547864,
	3512288486, 3539095424, 2818855152, 2690780513, 48448594, 615997303,
	3158320071, 336669172, 2591989774, 78738084, 2920659994, 286581664,
	2508088193, 1969602480, 2463253848, 486799861, 1550558230, 119328546,
	4117584734, 3242105365, 4238887108, 1695869891, 1662734000, 3208076406,
	3591365778, 1943063905, 4218269323, 1933107851, 2514071929, 2053305780,
	2881631052, 2035831364, 370469037, 3449560256, 4258247769, 1728262696,
	3347927815, 3885597447, 4270764278, 159175969, 2807576122, 3323764999,
	160751778, 539625604, 3088465285, 2656495549, 2955436150, 44514151,
	2614832306, 2313386572, 456173997, 12962046, 1205532000, 4085346197,
	3333816434, 3888672125, 3823235164, 3418651975, 2193007324, 3931073263,
	3073942169, 625167849, 334057719, 677445473, 2642711553, 805871885,
	3598340212, 2673599526, 2989320405, 3890422171, 2383961766, 4251825108,
	3698781345, 3054247681, 3201131518, 3143058847, 1136230645, 3905384561,
	4293975666, 1721739558, 2464159772, 1073100491, 2744737394, 744876899,
	2103243807, 513064115, 3819835458, 3490135875, 3755992992, 630468426,
	3641230240, 1135149025, 2781952773, 3517961216, 2515041189, 1333962094,
	1209388872, 4219450795, 4259121516, 1145204504, 3434518672, 2292023677,
	2154511200, 1350625504, 3317069097, 3911739544, 533778709, 1574348793,
	3955741595, 1862264878, 192571683, 2200280382, 981850180, 4032486718,
	3618451325, 132924960, 1312420089, 3078970413, 2080145240, 3826897254,
	2791958899, 117197738, 618229817, 2242193049, 1313393440, 1400115560,
	3809294369, 3691478518, 3808957062, 2398810305, 2212838707, 2964506143,
	1147132295, 1944990971, 3781046413, 2698566783, 2138822019, 1245956508,
	1432110735, 40151837, 3842692674, 2477147887, 878247997, 1337642707,
	3520175200, 2221647418, 3602781138, 3935933160, 2245391866, 1831695266,
	695517982, 1062557881, 4075825248, 1594694577, 255331836, 4002313006,
	3807486291, 4023819049, 2466789652, 3626369528, 1627135016, 3952256888,
	2752667134, 978824302, 548926898, 375733240, 1746775542, 976287876,
	1530769673, 1350237308, 649210240, 750613722, 3678523797, 2607449595,
	438119498, 1776340117, 4093623542, 3506203041, 716459895, 795128998,
	1887227685, 3014536747, 688983143, 1032319521, 3776443487, 2466252201,
	2054928583, 1498890309, 1714350790, 244660247, 1183135446, 982747242,
	221797415, 2852298783, 595774757, 2135672870, 3344226488, 2229156695,
	764733340, 750417316, 2505849410, 2451205898, 3986261460, 4281023360,
	462412816, 3508280094, 1944092547, 2552811004, 669982670, 4191841132,
	1306575547, 3872181813, 3281887353, 2558116592, 2692609267, 139270006,
	3054131141, 401910577, 830906826, 280769387, 293909166, 1940179099,
	3778093729, 1612480328, 1373740612, 4189096487, 2596221856, 721482735,
	4102596449, 4178090887, 1785813537, 3296279486, 841347854, 3540074573,
	713086891, 2717064253, 2683525973, 2872185380, 241779468, 2048194042,
	1411123637, 56420214, 4210836762, 1516149586, 3313985509, 2113432314,
	899075967, 3135717859, 2513767948, 2012743401, 1888875363, 1964539161,
	2635195109, 591256961, 1374266860, 46766761, 480605803, 3256780343,
	1344387639, 1374186944, 4268930703, 4227894748, 711994664, 945898812,
	1988226630, 1454739889, 2729525426, 2250116768, 159291610, 3242234132,
	1087804724, 1992253990, 3737534913, 536108752, 599711673, 1342183220,
	77614169, 2166893331, 2962298846, 2894159424, 3741250559, 3307768874,
	1526896431, 559787925, 1704239201, 98419713, 3706177625, 2229441574,
	4004014074, 3478875020, 1935994736, 54132754, 4187555789, 2888235981,
	2997617112, 2949818860, 3236732378, 1929500115, 2481521959, 3928987490,
	578129023, 2767509775, 3469040933, 22504934, 449548256, 2080604324,
	1441010018, 3690741887, 2423926771, 3566538990, 2673997569, 2788096032,
	1967528606, 2893512677, 3491186695, 2484636784, 1066273842, 1177335474,
	1815764986, 2407457952, 3460074283, 2885057449, 2354170565, 1513673729,
	1063118433, 3675754870, 46264499, 837679646, 1060515410, 3209718449,
	1073182033, 1243834322, 2644683487, 3323442631, 1124995837, 1837117845,
	2251747858, 3469038254, 1633183916, 1518420699, 155004041, 917805444,
	3623262285, 3295461887, 1932590911, 1325607063, 4193953887, 3149263603,
	246734011, 3197487845, 700463741, 950891584, 784236498, 919604639,
	2324833921, 854474836, 1171232718, 612111593, 2118571076, 1619557430,
	3152261145, 114365907, 793518491, 476399354, 3954364984, 2897230428,
	2834948872, 3435014071, 2963851117, 345871692, 721925294, 995153841,
	2945289227, 891745416, 2584730045, 3939917642, 2813036695, 3055072600,
	2223479001, 2378916306, 298433746, 1307894789, 2035114863, 3585670826,
	2081958702, 1869624853, 2653853619, 3966214261, 432594505, 3032469418,
	121416589, 2053128850, 291923095, 542068269, 1614406111, 4192075133,
	3319298612, 686480289, 1748612790, 870169486, 4015599545, 1851911535,
	2287831485, 1736033960, 1917317873, 630292808, 1412267969, 3132400918,
	1477748738, 810653910, 203856129, 2765510728, 1926754611, 3239719367,
	3879348080, 905088727, 3785706573, 2581078846, 3491618352, 3216622848,
	4124146218, 2741128487, 1316624899, 2564642233, 3986876203, 1269086773,
	192963499, 3142225866, 1546757986, 4060068853, 326493025, 1827772235,
	3974675131, 3359445314, 1451799370, 241123931, 3397233925, 3587464218,
	3217456067, 825707551, 2000726539, 1696928131, 353587894, 1288838273,
	858843149, 344042555, 327144316, 3885360568, 3833103057, 1589800072,
	3096548390, 2279328132, 1922801990, 2122213196, 2475828041, 567627781,
	865292751, 886713428, 3094600891, 327228447, 3639314906, 2181507079,
	2441921771, 1123346754, 2604647584, 1533567918, 3866642891, 464137042,
	3836764460, 3382509376, 2578611749, 457774255, 3367360969, 4233587162,
	3385879892, 760901391, 4212326849, 2458461236, 2948766405, 192609218,
	3951143257, 3380638748, 298053395, 814351339, 2282596113, 2267330309,
	2508689645, 3178608847, 1660574090, 643950846, 1122104733, 2366901393,
	1929795793, 930363822, 2351887367, 3260722193, 3633212146, 3104897110,
	3503813949, 758272320, 1122121223, 3702118173, 4217896631, 84933404,
	3985977204, 3694689763, 1441701931, 2400473570, 3026071607, 1731818728,
	2788011269, 3258793266, 896749404, 3079186623, 3197480628, 4240533609,
	4199266210, 1194366178, 1785006035, 16293709, 393239717, 4011081177,
	1122267062, 3684640004, 982923051, 3130390667, 3571011101, 2219161420,
	2262649305, 3036353952, 140443314, 3352348904, 3267796659, 1610079914,
	1818375575, 3308510067, 760249469, 3223906905, 3011798059, 2633722110,
	2566663538, 1726001011, 1183623784, 2994915160, 265601119, 13369628,
	3027455040, 3328155762, 1538432214, 3850079998, 3106280250, 1027853144,
	2263338623, 518691123, 407773078, 946112522, 1530957675, 1297495583,
	3908349428, 3792578569, 767366247, 2332882054, 826470046, 1231417155,
	864607890, 594228876, 524647753, 1246160970, 2704418139, 2636556225,
	4080025813, 1392164405, 172208298, 1964347014, 1993865609, 1907468452,
	299371510, 3556814295, 2550540475, 1831151368, 2570883509, 1484765143,
	1505189394, 2898980970, 1125246997, 951258179, 1345714685, 2006805518,
	3886559252, 1351908331, 1739409788, 2692324309, 3033825545, 3768234538,
	2364548034, 1922809620, 1933327723, 3369218960, 1988554554, 1962652749,
	443668522, 2818483491, 4080355147, 566252700, 539001578, 1859641429,
	563559458, 3905465260, 689030378, 2600512502, 3736972508, 3293271762,
	4239569288, 2167672606, 4032327232, 2139132621, 1640830226, 3620227238,
	2071236852, 291228555, 2877147064, 2462185652, 3490939603, 4049134412,
	3942947780, 2224191981, 376495129, 835224296, 551960931, 3641871941,
	3158792735, 1080781883, 4135500094, 3009595421, 2435810626, 2320403067,
	4068258848, 4075220807, 3680461049, 2681505724, 3021506556, 3599087965,
	773594312, 34071451, 2660020065, 4249183197, 2396929092, 333781542,
	268474684, 1383535713, 1886003702, 4063693577, 3693519683, 38393166,
	45646655, 3533598484, 365758883, 3698875831, 1841462003, 1889058972,
	2523141805, 1098417244, 3691746744, 3447525242, 2639655731, 2052401668,
	2286720719, 576979915, 3592519711, 3985081060, 3195718732, 3848161716,
	1408179450, 2111170342, 1050945107, 3679509200, 2811253615, 1797778916,
	2614702154, 2935459398, 292348826, 1709356772, 1660428473, 2172145438,
	2303752291, 814118336, 3834980134, 4144595858, 4034397151, 1263646761,
	936733170, 444355423, 2413049657, 619829936, 576185002, 60525937, 3044347122,
	3074963380, 658046614, 2424501824, 10937286, 3412688061, 60144828,
	2177891693, 934632544, 3400845467, 3886283008, 2988284570, 271748914,
	3340833782, 1255415060, 1745830650, 622882842, 2782153665, 2798365029,
	772210637, 617215464, 1382206226, 1335595964, 741331197, 4100755922,
	1755083494, 3940653371, 1036885621, 3644482929, 1747716670, 2256025074,
	4188548087, 415641254, 1375761047, 628460100, 4219766469, 1782855869,
	2732914007, 2254308802, 1611003667, 1211339511, 3682867876, 1126219537,
	2661104789, 1962706125, 1082473834, 1700820856, 3405289203, 3135143578,
	1859456753, 25802144, 1535498760, 2635905928, 1418528660, 133988334,
	2995176516, 269338194, 1153843510, 1106436088, 3471527637, 2542143871,
	1268255719, 378844893, 2336983543, 3698152138, 2095606873, 311234327,
	3673727838, 1412104154, 3815590669, 3481370622, 791925131, 4007842730,
	2514052490, 1060828376, 3857761304, 2381798191, 1916058873, 2407241156,
	3959394219, 2049763035, 1198256761, 1932011661, 2614909958, 4019503106,
	2931116355, 1675352413, 980136170, 201330052, 59131036, 1098258467,
	1789815781, 1857798098, 4030749030, 1263375565, 1473294510, 2326032462,
	3348976233, 3266903430, 750486747, 3894641488, 1468676244, 3314302103,
	621042495, 2426087907, 3078507207, 736315654, 3003503381, 1828218816,
	2957073458, 3217778778, 1088327689, 141565545, 2973664092, 2070593475,
	976235506, 2240795221, 1823854063, 2308600865, 1597393351, 700838009,
	1526035848, 2740522471, 247625523, 1014468641, 2712901607, 673494654,
	3037901667, 1669094845, 2635343367, 2158894077, 2784482107, 711386537,
	729889819, 2392028979, 641869096, 3480843130, 2208364999, 585597796,
	3759525421, 3330111326, 790073993, 4218727151, 1987878872, 4048199726,
	1842250361, 1456984634, 2135840789, 2976786358, 693683456, 2843964051,
	1470771347, 3556136789, 1124767771, 3635674209, 3627215592, 2383902958,
	3437400810, 2891570581, 1832401246, 2141396207, 2607111570, 34264771,
	624770042, 3058298147, 2188772447, 2183888925, 1275378023, 818360598,
	3692172728, 3698360567, 2884493066, 3494961962, 2720750152, 3097636383,
	535802764, 259121746, 2021159559, 45862615, 4237297800, 4221076797,
	4072913943, 2612669934, 2770621730, 5076958, 651653371, 2022948995,
	2745028919, 2314924528, 2429500266, 2410877892, 2012904432, 3960432655,
	1838406936, 2795596766, 2573844030, 272884842, 3650592889, 1310077466,
	3226040308, 2111911522, 2488334573, 1767581231, 3971574231, 1365220840,
	278056099, 2097156596, 4257800848, 269361367, 227609839, 486605274,
	856826830, 4075223383, 1815708857, 3229324568, 461747127, 435537713,
	2678644020, 2512288536, 206126479, 3897826499, 1222450249, 2762927278,
	262150548, 2854189378, 3021592542, 966383628, 2870997401, 349814400,
	1625991265, 390790370, 808288205, 16509067, 3208361306, 4112120600,
	1461917939, 278281270, 3415792491, 3285362428, 2095518569, 2343999151,
	2257733069, 2146671479, 122367272, 376016315, 2766955487, 55896806,
	1506058233, 278623055, 984428121, 40025065, 1863514911, 4175153646,
	1642685240, 639261426, 2017728545, 2575658406, 4206848988, 1768808939,
	1564991892, 3169033102, 3326066185, 2733919722, 2374118723, 3955438161,
	3818788943, 2895546243, 1524510895, 981046726, 1054494718, 1873428906,
	3912797829, 2194924948, 186978233, 4173505723, 4083454902, 10991565,
	2389749528, 278482234, 1616467694, 3635743823, 4273717156, 4060802000,
	250665658, 3289958195, 2219236927, 2796708809, 133560915, 3500777176,
	2453181138, 9864824, 775106359, 1086076916, 2709949134, 1418492870,
	4213035124, 432295963, 3757677847, 2770809781, 1940621893, 3544681924,
	3042816279, 1525764526, 3339202855, 929551426, 2125334861, 2042241642,
	2270034074, 960110360, 647614079, 1577810321, 1586560599, 3173976833,
	610835629, 1978873786, 3121984917, 306229487, 2048755217, 1439451832,
	1927919905, 2620209579, 3805332299, 3016883682, 2266105346, 3735792992,
	1757031770, 23668819, 1154882458, 1282936218, 309289331, 3217543092,
	1795881015, 3707914247, 110610366, 3851295459, 1250496671, 1714525007,
	2162556892, 1882249676, 4148650926, 1662252887, 469796038, 966719301,
	2890689335, 634280028, 2147193186, 11113175, 3337611477, 3290884170,
	616787343, 4207252085, 357352590, 3547785784, 1714630871, 797725697,
	3422926804, 3274937035, 823241036, 812636399, 3297577946, 1461261970,
	1246820414, 2613894061, 931541825, 2962648372, 71792924, 1666865751,
	1712227622, 1157053588, 1636732513, 4055561395, 2831864942, 1307589179,
	304592222, 2510535104, 655429134, 1823450593, 71192884, 1471273004,
	488751632, 1791212224, 2799413613, 3267779693, 1729398011, 3704621982,
	1378797522, 2215135204, 2396213770, 1251331117, 4266880216, 923803214,
	3584092263, 4115180387, 3004858683, 4285525857, 3943890602, 2361331392,
	170633477, 3209981530, 302079820, 3161338423, 2035841521, 1288085802,
	1499662612, 3688245998, 4025466968, 1469717444, 2102665490, 3407252572,
	2317775281, 2035605715, 3845113999, 1103349265, 1918282941, 410734727,
	3766834044, 454125031, 1089125312, 1129255991, 1176003714, 1702754778,
	1410301427, 3180329092, 2351770640, 1365503437, 945445444, 2128388382,
	2883766324, 3674137556, 613292452, 4258375010, 404157627, 204088050,
	3737445092, 429661727, 1017343340, 969485219, 1657874592, 1539057458,
	2454754611, 609711109, 2258302241, 3370735744, 326520073, 1599727135,
	3754342307, 265608024, 4085096380, 3109692966, 3489692299, 1502076204,
	1218919595, 2099382023, 2267084734, 3036678256, 1457783736, 2331508320,
	2382277981, 1072842164, 4185031016, 3233345176, 1338753835, 1834864307,
	2872459530, 4041903198, 1400018481, 4155454226, 3326354556, 138279050,
}

func TestMT19937(t *testing.T) {
	mt := NewMT19937(1)
	for _, x := range MT19937TestVector {
		if res := mt.ExtractNumber(); res != x {
			t.Fatalf("Wrong number, expected %d, got %d", x, res)
		}
	}
}

func TestRandomNumberFromTimeSeed(t *testing.T) {
	number, seed := RandomNumberFromTimeSeed()
	res := RecoverTimeSeed(number)
	if res != seed {
		t.Errorf("Time recovered incorrectly %d, but want %d", res, seed)
	}
}

func TestUntemperMT19937(t *testing.T) {
	for i := 0; i < 100000; i++ {
		y := mathrand.Uint32()
		x := y

		y ^= y >> 11
		y ^= y << 7 & 2636928640
		y ^= y << 15 & 4022730752
		y ^= y >> 18

		res := UntemperMT19937(y)
		if x != res {
			t.Fatalf("Wrong number at iteration %d, expected %d, got %d", i, x, res)
		}
	}

	mt := NewMT19937(uint32(time.Now().UnixMilli()))
	clone := NewMT19937(0)
	for i := 0; i < 624; i++ {
		clone.mt[i] = UntemperMT19937(mt.ExtractNumber())
	}
	for i := 0; i < 2000; i++ {
		if clone.ExtractNumber() != mt.ExtractNumber() {
			t.Fail()
		}
	}
}
