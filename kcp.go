// Package kcp - A Fast and Reliable ARQ Protocol
package kcp

import (
	"encoding/binary"
	"container/list"
)

const (
	IKCP_RTO_NDL     = 30  			// nodelay模式下最小rto
	IKCP_RTO_MIN     = 100			// normal模式下最小rto
	IKCP_RTO_DEF     = 200			// rto
	IKCP_RTO_MAX     = 60000		// 最大rto
	IKCP_CMD_PUSH    = 81 			// cmd: push data
	IKCP_CMD_ACK     = 82 			// cmd: ack
	IKCP_CMD_WASK    = 83 			// cmd: window probe (ask)
	IKCP_CMD_WINS    = 84 			// cmd: window size (tell)
	IKCP_ASK_SEND    = 1  			// need to send IKCP_CMD_WASK
	IKCP_ASK_TELL    = 2  			// need to send IKCP_CMD_WINS
	IKCP_WND_SND     = 32			// 发送窗口大小
	IKCP_WND_RCV     = 32			// 接收窗口大小
	IKCP_MTU_DEF     = 1400			// 最大传输单元
	IKCP_ACK_FAST    = 3			// 快重传ack跨越次数
	IKCP_INTERVAL    = 100			// 刷新间隔
	IKCP_OVERHEAD    = 24			// kcp包首部大小
	IKCP_DEADLINK    = 20			// kcp最大重传次数
	IKCP_THRESH_INIT = 2			// 初始化慢启动门限值
	IKCP_THRESH_MIN  = 2			// 慢启动门限最小值
	IKCP_PROBE_INIT  = 7000   		// 7 secs to probe window size
	IKCP_PROBE_LIMIT = 120000 		// up to 120 secs to probe window
)

// encode 8 bits unsigned int
func ikcp_encode8u(p []byte, c byte) []byte {
	p[0] = c
	return p[1:]
}

// decode 8 bits unsigned int
func ikcp_decode8u(p []byte, c *byte) []byte {
	*c = p[0]
	return p[1:] 
}

// encode 16 bits unsigned int (lsb)
func ikcp_encode16u(p []byte, w uint16) []byte {
	binary.LittleEndian.PutUint16(p,w)
	return p[2:]
}

// decode 16 bits unsigned int (lsb)
func ikcp_decode16u(p []byte, w *uint16) []byte {
	*w = binary.LittleEndian.Uint16(p)
	return p[2:]
}

// encode 32 bits unsigned int (lsb)
func ikcp_encode32u(p []byte, l uint32) []byte {
	binary.LittleEndian.PutUint32(p,l)
	return p[4:]
}

// decode 32 bits unsigned int (lsb)
func ikcp_decode32u(p []byte, l *uint32) []byte {
	*l = binary.LittleEndian.Uint32(p)
	return p[4:]
}

func _imin_(a, b uint32) uint32 {
	if a <= b {
		return a
	}
	return b
}

func _imax_(a, b uint32) uint32 {
	if a >= b {
		return a
	}
	return b
}

func _ibound_(lower, middle, upper uint32) uint32 {
	return _imin_(_imax_(lower, middle), upper)
}

func _itimediff_(later, earlier uint32) int32 {
	return (int32)(later - earlier)
}

// define segment
type IKCPSEG struct {
	conv     		uint32    // 连接号
	cmd      		uint8     // 命令号
	frg      		uint8     // 分片编号
	wnd      		uint16    // 窗口大小
	ts       		uint32    // 时间戳
	sn       		uint32    // 分片的序列号
	una      		uint32    // 未确认的分片的序列号
	len      		uint32    // 数据长度
	resendts 		uint32    // 重传时间戳
	rto      		uint32    // rto
	fastack  		uint32    // 快重传标记
	xmit     		uint32    // 分片已发送次数
	data     		[]byte    // 数据
}

// define kcp
type IKCPCB struct {
	conv            uint32    // 连接号
	mtu		 		uint32	  // 最大传输单元
	mss      		uint32    // 最大分片大小
	state    		uint32    // 连接状态 (0xffffffff 表示断开连接)
	snd_una  		uint32    // 第一个未确认的分片编号
	snd_nxt  		uint32    // 待发送的分片编号
	rcv_nxt  		uint32    // 待接收的分片编号
	ts_recent		uint32
	ts_lastack		uint32
	ssthresh		uint32	  // 慢启动门限
	rx_rttval       uint32    // rttd
	rx_srtt         uint32    // rtts
	rx_rto          uint32    // rto
	rx_minrto       uint32    // 最小rto
	snd_wnd			uint32    // 发送窗口大小
	rcv_wnd			uint32    // 接收窗口大小
	rmt_wnd			uint32    // 远端接收窗口大小
	cwnd			uint32    // 拥塞窗口大小
	probe			uint32    // 探测变量
	current			uint32    // 当前时间
	interval        uint32    // 内部flush刷新时间间隔
	ts_flush        uint32    // 下次flush刷新时间
	xmit            uint32    // kcp重传次数
	nrcv_buf		uint32    // rcv_buf长度
	nsnd_buf		uint32    // snd_buf长度
	nrcv_que		uint32    // rcv_que长度
	nsnd_que		uint32    // snd_que长度
	nodelay			uint32    // 是否启动nodelay模式
	updated			uint32    // 是否调用过update函数
	ts_probe		uint32    // 下次探测窗口的时间戳
	probe_wait      uint32    // 探测窗口需要等待的时间
	dead_link       uint32	  // 最大重传次数
	incr            uint32    // 可发送的最大数据量
	snd_queue *list.List      // 发送队列
	rcv_queue *list.List      // 接收队列
	snd_buf *list.List        // 发送缓存
	rcv_buf *list.List        // 接收缓存
	acklist *list.List         // 待发送的ack列表
	ackcount        uint32    // 待发送的ack数量
	ackblock        uint32    // 
	user interface{}          // 用户
	buffer []byte             // 存储发送字节流的缓存
	fastresend      int32     // 触发快速重传的ack个数
	nocwnd          int32     // 取消拥塞控制
	logmask         int32     // 
	writelog func (log []byte, kcp *IKCPCB, user []byte) //
	Output func (buf []byte, _len int32, kcp *IKCPCB, user interface{}) (int32) //
}

// define ackItem
type ACKITEM struct {
	sn uint32
	ts uint32
}

// create a new segment
func ikcp_segment_new(kcp *IKCPCB, size int) *IKCPSEG {
	seg := new(IKCPSEG)
	seg.data = make([]byte, size)
	return seg
}

// output segment
func ikcp_output(kcp *IKCPCB, data []byte, size int32) int32 {
	if 0 == size {
		return 0
	}
	return kcp.Output(data, size, kcp, kcp.user)
}

// create a new kcp
func Ikcp_create(conv uint32, user interface{}) *IKCPCB {
	kcp := &IKCPCB{}
	kcp.conv = conv
	kcp.user = user
	kcp.snd_una = 0
	kcp.snd_nxt = 0
	kcp.rcv_nxt = 0
	kcp.ts_recent = 0
	kcp.ts_lastack = 0
	kcp.ts_probe = 0
	kcp.probe_wait = 0
	kcp.snd_wnd = IKCP_WND_SND
	kcp.rcv_wnd = IKCP_WND_RCV
	kcp.rmt_wnd = IKCP_WND_RCV
	kcp.cwnd = 0
	kcp.incr = 0
	kcp.probe = 0
	kcp.mtu = IKCP_MTU_DEF
	kcp.mss = kcp.mtu - IKCP_OVERHEAD
	kcp.buffer = make([]byte, (kcp.mtu+IKCP_OVERHEAD)*3)		// 设置buffer大小
	kcp.snd_queue = list.New()
	kcp.rcv_queue = list.New()
	kcp.snd_buf = list.New()
	kcp.rcv_buf = list.New()
	kcp.nrcv_buf = 0
	kcp.nsnd_buf = 0
	kcp.nrcv_que = 0
	kcp.nsnd_que = 0
	kcp.state = 0
	kcp.acklist = list.New()
	kcp.ackblock = 0
	kcp.ackcount = 0
	kcp.rx_srtt = 0
	kcp.rx_rttval = 0
	kcp.rx_rto = IKCP_RTO_DEF
	kcp.rx_minrto = IKCP_RTO_MIN
	kcp.current = 0
	kcp.interval = IKCP_INTERVAL
	kcp.ts_flush = IKCP_INTERVAL
	kcp.nodelay = 0
	kcp.updated = 0
	kcp.logmask = 0
	kcp.ssthresh = IKCP_THRESH_INIT
	kcp.fastresend = 0
	kcp.nocwnd = 0
	kcp.xmit = 0
	kcp.dead_link = IKCP_DEADLINK
	kcp.Output = nil
	kcp.writelog = nil

	return kcp
}

// release a kcp

// recv data
func Ikcp_recv(kcp *IKCPCB, buffer []byte, len int32) int32 {
	var peeksize int
	var length int

	// rcv_queue队列为空
	if 0 == kcp.rcv_queue.Len() {
		return -1
	}

	if len < 0 {
		len = -len
	}

	peeksize = Ikcp_peeksize(kcp)

	// peeksize < 0 说明IKCP_peeksize(kcp)返回错误码
	if peeksize < 0 {
		return -2
	}

	// buffer空间不足以装下整个数据
	// 此处的len为buffer空间大小
	if peeksize > int(len) {
		return -3
	}

	// 快速恢复
	var fast_recover bool
	if kcp.rcv_queue.Len() >= int(kcp.rcv_wnd) {
		fast_recover = true
	}

	// merge fragment
	for p := kcp.rcv_queue.Front(); p != nil; p = p.Next() {
		seg := p.Value.(*IKCPSEG)
		copy(buffer, seg.data[:seg.len])
		buffer = buffer[seg.len:]
		length += int(seg.len)

		// 移除rcv_queue中的节点
		q := p.Next()
		kcp.rcv_queue.Remove(p)
		p = q

		// 数据全部合并 break
		if 0 == seg.frg {
			break;
		}
	}

	// 将可用的分片从rcv_buf移动到rcv_queue
	for p := kcp.rcv_buf.Front(); p != nil; p = p.Next() {
		seg := p.Value.(*IKCPSEG)

		// 当前分片的序列号等于下一个要接收的包的序列号
		// 且kcp.rcv_queue的长度小于rcv_wnd(接收窗口长度)
		if seg.sn == kcp.rcv_nxt && kcp.rcv_queue.Len() < int(kcp.rcv_wnd){
			q := p.Next()
			kcp.rcv_buf.Remove(p)
			p = q
			kcp.rcv_queue.PushBack(seg)

			// rcv_nxt 序列号加1
			kcp.rcv_nxt++
		} else {
			break
		}
	}

	// 快速恢复
	if kcp.rcv_queue.Len() < int(kcp.rcv_wnd) && fast_recover {
		// 设置kcp.probe的值
		// 准备在flush()中发送IKCP_ASK_TELL 告知远端本窗口大小
		kcp.probe |= IKCP_ASK_TELL
	}

	return int32(length)
}

// calculate size
func Ikcp_peeksize(kcp *IKCPCB) int {
	var length int

	if 0 == kcp.rcv_queue.Len() {
		return -1
	}

	// rcv_queue队首分片编号为0
	// 说明数据只由一个分片承载
	seg := kcp.rcv_queue.Front().Value.(*IKCPSEG)
	if 0 == seg.frg {
		return int(seg.len)
	}

	// rcv_queue队列长度小于所有分片个数
	// 说明数据不完整
	if kcp.rcv_queue.Len() < int(seg.frg + 1) {
		return -1
	}

	// 遍历rcv_queue队列
	// 当seg.frg == 0时说明此分片为最后一个分片
	for p := kcp.rcv_queue.Front(); p != nil; p = p.Next() {
		seg = p.Value.(*IKCPSEG)
		length += int(seg.len)
		if 0 == seg.frg {
			break;
		}
	}

	return length
}

// send data
func Ikcp_send(kcp *IKCPCB, buffer []byte, len int) int {
	var count int
	var seg *IKCPSEG

	if len <= 0 {
		return -1
	}

	// 流模式

	// 分片
	if len <= int(kcp.mss) {
		count = 1
	} else {
		count = (len + int(kcp.mss) - 1) / int(kcp.mss)
	}

	// frg为uint8
	if count > 255 {
		return -2
	}

	if 0 == count {
		count = 1
	}

	for i := 0; i < count; i++ {
		var size int 

		// 确定分片数据大小
		if len <= int(kcp.mss) {
			size = len
		} else {
			size = int(kcp.mss)
		}

		// 创建分片
		seg = ikcp_segment_new(kcp, size)
		if buffer != nil && len > 0 {
			copy(seg.data, buffer[:len])
		}

		// 流模式frg未添加
		seg.frg = uint8(count - i - 1)
		seg.len = uint32(size)
		kcp.snd_queue.PushBack(seg)

		if buffer != nil {
			buffer = buffer[size:]
		}
		len -= size
	}

	return 0
}

// parse ack
func Ikcp_update_ack(kcp *IKCPCB, rtt int32)  {
	rto := 0
	if 0 == kcp.rx_srtt {
		kcp.rx_srtt = uint32(rtt)
		kcp.rx_rttval = kcp.rx_srtt / 2
	} else {
		delta := rtt - int32(kcp.rx_srtt)
		if delta < 0 {
			delta = -delta
		}
		kcp.rx_rttval = (3 * kcp.rx_rttval + uint32(delta)) / 4
		kcp.rx_srtt = (7 * kcp.rx_srtt  + uint32(rtt)) / 8
		if kcp.rx_srtt < 1 {
			kcp.rx_srtt = 1
		}
	}
	rto = int(kcp.rx_srtt + _imax_(kcp.interval, 4 * kcp.rx_rttval))
	kcp.rx_rto = _ibound_(kcp.rx_minrto, uint32(rto), IKCP_RTO_MAX)
}

// ikcp_shrink_buf
func ikcp_shrink_buf(kcp *IKCPCB)  {
	if kcp.snd_buf.Len() > 0 {
		p := kcp.snd_buf.Front()
		seg := p.Value.(*IKCPSEG)
		kcp.snd_una = seg.sn
	} else {
		kcp.snd_una = kcp.snd_nxt
	}
}

// parse ack
func ikcp_parse_ack(kcp *IKCPCB, sn uint32)  {
	// ack 不在发送窗口内
	if _itimediff_(sn, kcp.snd_una) < 0 || _itimediff_(sn, kcp.snd_nxt) >= 0 {
		return
	}

	for p := kcp.snd_buf.Front(); p != nil; p = p.Next() {
		seg := p.Value.(*IKCPSEG)
		// 找到对应分片，从snd_buf中删除
		if sn == seg.sn {
			kcp.snd_buf.Remove(p)
			break
		}
		// 确认号小于当前分片号，说明对应的分片已经被确认
		if _itimediff_(sn, seg.sn) < 0 {
			break
		}
	}
}

// parse fastack
func ikcp_parse_fastack(kcp *IKCPCB, sn uint32)  {
	// sn不在发送窗口中
	if _itimediff_(sn, kcp.snd_una) < 0 || _itimediff_(sn, kcp.snd_nxt) >= 0 {
		return
	}

	// fastack计数
	for p := kcp.snd_buf.Front(); p != nil; p = p.Next() {
		seg := p.Value.(*IKCPSEG)
		if _itimediff_(sn, seg.sn) < 0{
			break
		} else if sn != seg.sn {
			seg.fastack++
		}	
	}
}

// parse una
func ikcp_parse_una(kcp *IKCPCB, una uint32)  {
	for p := kcp.snd_buf.Front(); p != nil; {
		seg := p.Value.(*IKCPSEG)
		if _itimediff_(una, seg.sn) > 0 {
			q := p.Next()
			kcp.snd_buf.Remove(p)
			p = q
		} else {
			break
		}
	}
}

// ack append
func ikcp_ack_push(kcp *IKCPCB, sn, ts uint32)  {
	var ack *ACKITEM = new(ACKITEM)
	ack.sn, ack.ts = sn, ts
	kcp.acklist.PushBack(ack)
}

// parse data
func ikcp_parse_data(kcp *IKCPCB, newseg *IKCPSEG)  {
	var p *list.Element
	sn := newseg.sn
	repeat := 0

	// sn不在接收窗口内
	if _itimediff_(sn, kcp.rcv_nxt) < 0 || 
		_itimediff_(sn, kcp.rcv_nxt + kcp.rcv_wnd) >= 0{
		return
	}

	// 从后往前遍历rcv_buf找到新分片的插入点
	for p = kcp.rcv_buf.Back(); p != nil; p = p.Prev() {
		seg := p.Value.(*IKCPSEG)
		if sn == seg.sn {
			repeat = 1
			break
		}
		if _itimediff_(sn, seg.sn) > 0 {
			break
		}
	}

	// 不是重复的分片则插入
	if repeat == 0 {
		if p == nil {
			kcp.rcv_buf.PushFront(newseg)
		} else {
			kcp.rcv_buf.InsertAfter(newseg, p)
		}
	}

	// 将rcv_buf中的分片移动到rcv_queue
	for p := kcp.rcv_buf.Front(); p != nil;{
		seg := p.Value.(*IKCPSEG)
		// sn为下一个要接收的分片，且接收窗口未满
		if seg.sn == kcp.rcv_nxt && kcp.rcv_queue.Len() < int(kcp.rcv_wnd) {
			kcp.rcv_queue.PushBack(seg)

			// 将当前分片从rcv_buf删除
			q := p.Next()
			kcp.rcv_buf.Remove(p)
			p = q

			kcp.rcv_nxt++
		} else {
			break
		}	
	}
}

// input data
func Ikcp_input(kcp *IKCPCB, data []byte, size int) int {
	snd_una := kcp.snd_una
	var maxack uint32 = 0
	flag := 0

	// data为空或data长度小于OVERHEAD
	if nil == data || size < int(IKCP_OVERHEAD) {
		return 0
	}

	// 解包
	for {
		var conv, ts, sn, una, len uint32
		var cmd, frg uint8
		var wnd uint16
		var seg *IKCPSEG

		if size < int(IKCP_OVERHEAD) {
			break
		}

		data = ikcp_decode32u(data, &conv)
		if conv != kcp.conv {
			return -1
		}

		data = ikcp_decode8u(data, &cmd)
		data = ikcp_decode8u(data, &frg)
		data = ikcp_decode16u(data, &wnd)
		data = ikcp_decode32u(data, &ts)
		data = ikcp_decode32u(data, &sn)
		data = ikcp_decode32u(data, &una)
		data = ikcp_decode32u(data, &len)

		size -= int(IKCP_OVERHEAD)

		// 剩余字节小于分片数据长度
		if uint32(size) < len {
			return -2
		}

		// 命令号不符合所有条件
		if cmd != uint8(IKCP_CMD_ACK) && cmd != uint8(IKCP_CMD_PUSH) &&
			cmd != uint8(IKCP_CMD_WASK) && cmd != uint8(IKCP_CMD_WINS) {
			return -3
		}

		// 远端窗口大小
		kcp.rmt_wnd = uint32(wnd)
		ikcp_parse_una(kcp, una)
		ikcp_shrink_buf(kcp)

		// 按照命令解析
		if cmd == uint8(IKCP_CMD_ACK) {
			if _itimediff_(kcp.current, ts) > 0 {
				// 更新rto
				Ikcp_update_ack(kcp, _itimediff_(kcp.current, ts))
			}
			// 确认
			ikcp_parse_ack(kcp, sn)
			ikcp_shrink_buf(kcp)

			// 设置最大ack
			if 0 == flag {
				flag = 1
				maxack = sn
			} else if _itimediff_(sn, maxack) > 0 {
				maxack = sn
			}
		} else if cmd == uint8(IKCP_CMD_PUSH) {
			// sn小于接收窗口最末端编号push ack (部分ack未送达)
			if _itimediff_(sn, kcp.rcv_nxt + kcp.rcv_wnd) < 0 {
				ikcp_ack_push(kcp, sn, ts)
				if _itimediff_(sn, kcp.rcv_nxt) >= 0 {
					seg = ikcp_segment_new(kcp, int(len))
					seg.conv = conv
					seg.cmd = cmd
					seg.frg = frg
					seg.wnd = wnd
					seg.ts = ts
					seg.sn = sn
					seg.una = una
					seg.len = len

					if len > 0 {
						copy(seg.data, data[:len])
					}

					ikcp_parse_data(kcp, seg)
				}
			}
		} else if cmd == uint8(IKCP_CMD_WASK) {
			// 更改kcp.probe的状态
			kcp.probe |= IKCP_ASK_TELL
		} else if cmd == uint8(IKCP_CMD_WINS) {
			// 不做处理
		} else {
			return -3
		}

		data = data[len:]
		size -= int(len)
	}

	// 快速重传ack
	if flag != 0 {
		ikcp_parse_fastack(kcp, maxack)
	}

	// 如果kcp.snd_una增加
	// 说明远端成功接收数据
	// 改变拥塞窗口
	if _itimediff_(kcp.snd_una, snd_una) > 0 {
		// 拥塞窗口小于远端窗口
		if kcp.cwnd < kcp.rmt_wnd {
			mss := kcp.mss
			// 拥塞窗口大小未超过慢启动门限
			if kcp.cwnd < kcp.ssthresh {
				kcp.cwnd++
				kcp.incr += kcp.mss
			} else {
				// 拥塞避免
				if kcp.incr < mss {
					kcp.incr = mss
				}
				kcp.incr += (mss*mss)/kcp.incr + (mss / 16)
				if (kcp.cwnd+1)*mss <= kcp.incr {
					kcp.cwnd++
				}
			}
			// 拥塞窗口大小等于远端窗口
			if kcp.cwnd > kcp.rmt_wnd {
				kcp.cwnd = kcp.rmt_wnd
				kcp.incr = kcp.rmt_wnd * mss
			}
		}
	}

	return 0
}

// encode a segment
func ikcp_encode_seg(ptr []byte, seg *IKCPSEG) []byte {
	ptr = ikcp_encode32u(ptr, seg.conv)
	ptr = ikcp_encode8u(ptr, seg.cmd)
	ptr = ikcp_encode8u(ptr, seg.frg)
	ptr = ikcp_encode16u(ptr, seg.wnd)
	ptr = ikcp_encode32u(ptr, seg.ts)
	ptr = ikcp_encode32u(ptr, seg.sn)
	ptr = ikcp_encode32u(ptr, seg.una)
	ptr = ikcp_encode32u(ptr, seg.len)
	return ptr
}

// calculate wnd unused
func ikcp_wnd_unused(kcp *IKCPCB) uint16 {
	if kcp.rcv_queue.Len() < int(kcp.rcv_wnd) {
		return uint16(int(kcp.rcv_wnd) - kcp.rcv_queue.Len())
	}
	return 0
}

// Ikcp_flush
func Ikcp_flush(kcp *IKCPCB)  {
	var seg IKCPSEG
	seg.conv = kcp.conv
	seg.cmd = IKCP_CMD_ACK
	seg.wnd = ikcp_wnd_unused(kcp)
	seg.una = kcp.rcv_nxt

	var  cwnd uint32
	lost := false
	change := false
	current := kcp.current
	buffer := kcp.buffer
	ptr := buffer

	// Ikcp_update 一次都没有调用过
	if 0 == kcp.updated {
		return 
	}

	// flush ack
	for p := kcp.acklist.Front(); p != nil; {
		size := len(buffer) - len(ptr)
		if size + IKCP_OVERHEAD > int(kcp.mtu) {
			ikcp_output(kcp, buffer, int32(size))
			ptr = buffer
		}
		ackItem := p.Value.(*ACKITEM)
		seg.sn = ackItem.sn
		seg.ts = ackItem.ts

		// 删除当前节点
		q := p.Next()
		kcp.acklist.Remove(p)
		p = q
		
		ptr = ikcp_encode_seg(ptr, &seg)
	}

	// for i, ack := range kcp.acklist {
	// 	// size为buffer中填充数据大小
	// 	size := len(buffer) - len(ptr)
	// 	if size + IKCP_OVERHEAD > int(kcp.mtu) {
	// 		ikcp_output(kcp, buffer, size)
	// 		ptr = buffer
	// 	}

	// 	seg.sn, seg.ts = ack.sn, ack.ts
	// 	ptr = ikcp_encode_seg(ptr, &seg)
	// }
	// kcp.acklist = kcp.acklist[0:0]

	// 探测窗口大小(如果远端窗口大小为0)
	if kcp.rmt_wnd == 0 {                                                   //远端窗口值为0
		if kcp.probe_wait == 0 {
			kcp.probe_wait = IKCP_PROBE_INIT
			kcp.ts_probe = kcp.current + kcp.probe_wait
		} else {
			if _itimediff_(kcp.current, kcp.ts_probe) >= 0 {
				if kcp.probe_wait < IKCP_PROBE_INIT {
					kcp.probe_wait = IKCP_PROBE_INIT
				}
				kcp.probe_wait += kcp.probe_wait / 2
				if kcp.probe_wait > IKCP_PROBE_LIMIT {
					kcp.probe_wait = IKCP_PROBE_LIMIT
				}
				kcp.ts_probe = kcp.current + kcp.probe_wait
				kcp.probe |= IKCP_ASK_SEND
			}
		}
	} else {
		kcp.ts_probe = 0
		kcp.probe_wait = 0
	}

	// 探测远端窗口大小
	if (kcp.probe & IKCP_ASK_SEND) != 0 {
		seg.cmd = IKCP_CMD_WASK
		size := len(buffer) - len(ptr)
		if int32(size)+int32(IKCP_OVERHEAD) > int32(kcp.mtu) {
			ikcp_output(kcp, buffer, int32(size))
			ptr = buffer
			size = 0
		}
		ptr = ikcp_encode_seg(ptr, &seg)
		size += 24
	}

	// 告知远端窗口大小
	if (kcp.probe & IKCP_ASK_TELL) != 0 {
		seg.cmd = IKCP_CMD_WINS
		size := len(buffer) - len(ptr)
		if int32(size)+int32(IKCP_OVERHEAD) > int32(kcp.mtu) {
			ikcp_output(kcp, buffer, int32(size))
			ptr = buffer
			size = 0
		}
		ptr = ikcp_encode_seg(ptr, &seg)
		size += 24
	}

	kcp.probe = 0

	// 计算拥塞窗口大小
	cwnd = _imin_(kcp.snd_wnd, kcp.rmt_wnd)
	if 0 == kcp.nocwnd {
		cwnd = _imin_(kcp.cwnd, cwnd)
	}

	// 将数据从snd_queue移动到snd_buf
	for p := kcp.snd_queue.Front(); p != nil; {
		// 分片编号不在发送窗口内 break
		if _itimediff_(kcp.snd_nxt, kcp.snd_una + cwnd) >= 0{			
			break
		}

		// 将分片加入snd_buf队列
		newseg := p.Value.(*IKCPSEG)
		newseg.conv = kcp.conv
		newseg.cmd = IKCP_CMD_PUSH
		newseg.sn = kcp.snd_nxt
		kcp.snd_buf.PushBack(newseg)

		// 删除snd_queue节点
		q := p.Next()
		kcp.snd_queue.Remove(p)
		p = q

		kcp.snd_nxt++
		//
		kcp.nsnd_que--
		kcp.nsnd_buf++		
	}

	// calculate resent
	resent := uint32(kcp.fastresend)
	if resent <= 0 {
		resent = 0xffffffff
	}

	// rtomin

	// flush data segment
	for p := kcp.snd_buf.Front(); p != nil; p = p.Next() {
		segment := p.Value.(*IKCPSEG)
		needsend := false
		if 0 == segment.xmit { // 初始发送
			needsend = true
			segment.rto = kcp.rx_rto
			segment.resendts = current + segment.rto
		} else if _itimediff_(current, segment.resendts) >= 0 {
			needsend = true
			kcp.xmit++

			// 重新计算rto
			if 0 == kcp.nodelay {
				segment.rto += kcp.rx_rto
			} else {
				segment.rto += kcp.rx_rto / 2
			}
			segment.resendts = current + segment.rto

			// 丢包
			lost = true
		} else if segment.fastack >= resent {
			needsend = true
			segment.fastack = 0
			segment.resendts = current + segment.rto

			// 触发快速重传
			change = true
		}

		// 发送数据
		if needsend {
			segment.xmit++
			segment.ts = current
			segment.wnd = seg.wnd
			segment.una = seg.una

			size := len(buffer) - len(ptr)
			need := IKCP_OVERHEAD + int(segment.len)

			if size + need > int(kcp.mtu) {
				ikcp_output(kcp, buffer, int32(size))
				ptr = buffer
			}

			ptr = ikcp_encode_seg(ptr,segment)
			copy(ptr, segment.data)
			ptr = ptr[segment.len:]

			// 断开连接
			if segment.xmit >= kcp.dead_link {
				kcp.state = 0xffffffff
			}
		}
	}

	// 发送剩余数据
	size := len(buffer) - len(ptr)
	if size > 0 {
		ikcp_output(kcp, buffer, int32(size))
	}

	// change
	if change {
		inflight := kcp.snd_nxt - kcp.snd_una
		kcp.ssthresh = inflight / 2
		if kcp.ssthresh < IKCP_THRESH_MIN {
			kcp.ssthresh = IKCP_THRESH_MIN
		}
		kcp.cwnd = kcp.ssthresh + resent
		kcp.incr = kcp.cwnd * kcp.mss
	}

	// lost
	if lost {
		kcp.ssthresh = cwnd / 2
		if kcp.ssthresh < IKCP_THRESH_MIN {
			kcp.ssthresh = IKCP_THRESH_MIN
		}
		kcp.cwnd = 1
		kcp.incr = kcp.mss
	}

	//cwnd
	if kcp.cwnd < 1 {
		kcp.cwnd = 1
		kcp.incr = kcp.mss  
	}
}

// update
func Ikcp_update(kcp *IKCPCB, current uint32)  {
	var slap int32
	kcp.current = current

	// 如果Ikcp_update()从未调用
	if 0 ==kcp.updated {
		kcp.updated = 1
		kcp.ts_flush = current
	}

	// 当前时间与flush时间差
	slap = _itimediff_(kcp.current, kcp.ts_flush)

	if slap >= 10000 || slap <= -10000 {
		kcp.ts_flush = kcp.current
		slap = 0
	}

	// 到达刷新时间
	// 调用Ikcp_flush()
	if slap >= 0 {
		kcp.ts_flush += kcp.interval
		if _itimediff_(current, kcp.ts_flush) >= 0 {
			kcp.ts_flush = kcp.current
		}
		Ikcp_flush(kcp)
	}
}

// Ikcp_check

// set mtu

// set interval

// set nodelay
func Ikcp_nodelay(kcp *IKCPCB, nodelay, interval, resend, nc int32) int32 {
	if nodelay >= 0 {
		kcp.nodelay = uint32(nodelay)
		if nodelay != 0 {
			kcp.rx_minrto = IKCP_RTO_NDL
		} else {
			kcp.rx_minrto = IKCP_RTO_MIN
		}
	}
	if interval >= 0 {
		if interval > 5000 {
			interval = 5000
		} else if interval < 10 {
			interval = 10
		}
		kcp.interval = uint32(interval)
	}
	if resend >= 0 {
		kcp.fastresend = resend
	}
	if nc >= 0 {
		kcp.nocwnd = nc
	}
	return 0
}

// set wndsize
func Ikcp_wndsize(kcp *IKCPCB, sndwnd, rcvwnd int32) int32 {
	if kcp != nil {
		if sndwnd > 0 {
			kcp.snd_wnd = uint32(sndwnd)
		}
		if rcvwnd > 0 {
			kcp.rcv_wnd = uint32(rcvwnd)
		}
	}
	return 0
}

// wait send