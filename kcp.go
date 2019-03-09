// Package kcp - A Fast and Reliable ARQ Protocol
package main

import (
	"encoding/binary"
	"container/list"
	"fmt"
)

const (
	IKCP_RTO_NDL     = 30  // no delay min rto
	IKCP_RTO_MIN     = 100 // normal min rto
	IKCP_RTO_DEF     = 200
	IKCP_RTO_MAX     = 60000
	IKCP_CMD_PUSH    = 81 // cmd: push data
	IKCP_CMD_ACK     = 82 // cmd: ack
	IKCP_CMD_WASK    = 83 // cmd: window probe (ask)
	IKCP_CMD_WINS    = 84 // cmd: window size (tell)
	IKCP_ASK_SEND    = 1  // need to send IKCP_CMD_WASK
	IKCP_ASK_TELL    = 2  // need to send IKCP_CMD_WINS
	IKCP_WND_SND     = 32
	IKCP_WND_RCV     = 32
	IKCP_MTU_DEF     = 1400
	IKCP_ACK_FAST    = 3
	IKCP_INTERVAL    = 100
	IKCP_OVERHEAD    = 24
	IKCP_DEADLINK    = 20
	IKCP_THRESH_INIT = 2
	IKCP_THRESH_MIN  = 2
	IKCP_PROBE_INIT  = 7000   // 7 secs to probe window size
	IKCP_PROBE_LIMIT = 120000 // up to 120 secs to probe window
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
	conv     uint32    // 连接号
	cmd      uint8     // 命令号
	frg      uint8     // 分片编号
	wnd      uint16    // 窗口大小
	ts       uint32    // 时间戳
	sn       uint32    // 分片的序列号
	una      uint32    // 未确认的分片的序列号
	len      uint32    // 数据长度
	resendts uint32    // 重传时间戳
	rto      uint32    // rto
	fastack  uint32    // 快重传标记
	xmit     uint32    // 分片已发送次数
	data     []byte    // 数据
}

// define kcp
type IKCPCB struct {
	current uint32 // 当前系统时间
	updated uint32 // Ikcp_update() 是否执行过的标记
	ts_flush uint32 // Ikcp_flush() 执行的时间戳
	interval uint32 // Ikcp_flush() 执行时间间隔
	//ackcount uint32 // ack列表中要发送的ack数量
	acklist []uint32 // ack列表
	snd_wnd uint32 // 发送窗口
	rmt_wnd uint32 // 远端窗口
	cwnd // 拥塞窗口
	nocwnd // 拥塞窗口标记
	snd_nxt uint32 // 下一个要发送的分片编号
	snd_una uint32 // 下一个待确认的分片编号
	nsnd_que uint32 // snd_que长度
	nsnd_buf uint32 // snd_buf 长度
	fastresend uint32 // 快速重传
	rx_rto uint32
	xmit uint32
	nodelay uint32 // 急速模式
	dead_link uint32 // 连接
	state uint32 // 连接状态
	snd_queue *list.List // 发送队列
	rcv_queue *list.List // 接收队列
	snd_buf *list.List // 发送缓存
	rcv_buf *list.List // 接收缓存

}

// define ackItem
type ackItem struct {
	sn uint32
	ts uint32
}
// create a new segment
func ikcp_segment_new(size int) *IKCPSEG {
	seg := new(IKCPSEG)
	seg.data = make([]byte, size)
	return seg
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

// output segment
func ikcp_output(kcp *IKCPCB, data []byte, size int)  {
	if 0 == size {
		return 0
	}
	return kcp.Output(data, size, kcp, kcp.user)
}

// create a new kcp
func Ikcp_create(conv uint32, user interface{}) *IKCPCB {

}

// release a kcp
func (kcp *IKCPCB)  {
	
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

// recv data
func Ikcp_recv(kcp *IKCPCB, buffer []byte, len int) int {
	var peeksize int
	var length int

	// rcv_queue队列为空
	if 0 == kcp.rcv_queue.len() {
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
	if peeksize > len {
		return -3
	}

	// 快速恢复
	var fast_recover bool
	if kcp.rcv_queue.len() >= int(kcp.rcv_wnd) {
		fast_recover = true
	}

	// merge fragment
	for p := kcp.rcv_queue.Front(); p != nil; p = p.Next() {
		seg := p.Value(*IKCPSEG)
		copy(buffer, seg.data[:seg.len])
		buffer = buffer[seg.len:]
		length += seg.len

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
		if seg.sn == kcp.rcv_nxt && kcp.rcv_queue.len() < kcp.rcv_wnd{
			q := p.Next()
			kcp,rcv_buf.Remove(p)
			p = q
			kcp.rcv_queue.PushBack(seg)

			// rcv_nxt 序列号加1
			kcp.rcv_nxt++
		} else {
			break
		}
	}

	// 快速恢复
	if ikcp.rcv_queue.Len() < int(ikcp.rcv_wnd) && fast_recover {
		// 设置kcp.probe的值
		// 准备在flush()中发送IKCP_ASK_TELL 告知远端本窗口大小
		kcp.probe |= IKCP_ASK_TELL
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

	if count > 255 {
		return -2
	}

	if 0 == count {
		count = 1
	}

	for i := 0; i < count; i++ {
		// 确定分片数据大小
		if len <= int(kcp.mss) {
			size := len
		} else {
			size = int(kcp.mss)
		}

		// 创建分片
		seg = ikcp_segment_new(kcp, size)
		if buffer != nil && len > 0 {
			copy(seg.data, buffer[:len])
		}

		// 流模式frg未添加
		seg.frg = uint32(count - i - 1)
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

// ack append

func ikcp_ack_push(kcp *IKCPCB, sn, ts uint32)  {
	kcp.acklist = append(kcp.acklist, ackItem{sn, ts})
}
// parse data

// input data

// calculate wnd unused
func ikcp_wnd_unused(kcp *IKCPCB) uint16 {
	if kcp.rcv_queue.Len() < int(kcp.rcv_wnd) {
		return uint16(kcp.rcv_wnd - kcp.rcv_queue.Len())
	}
	return 0
}

// Ikcp_flush
func Ikcp_flush(kcp *IKCPCB)  {
	var seg IKCPSEG
	seg.conv = kcp.conv
	seg.cmd = IKCP_CMD_ACK
	seg.wnd = ikcp_wnd_unused(kcp)
	seg.una = ikcp.rcv_nxt

	var count, cwnd int32
	lost := false
	change := false
	current := ikcp.current
	buffer := ikcp.buffer
	ptr := buffer

	// Ikcp_update 一次都没有调用过
	if 0 == ikcp.update {
		return 
	}

	// flush ack
	for i, ack := range kcp.acklist {
		// size为buffer中填充数据大小
		size := len(buffer) - len(ptr)
		if size + IKCP_OVERHEAD > int(kcp.mtu) {
			ikcp_output(kcp, buffer, size)
			ptr = buffer
		}

		seg.sn, seg.ts = ack.sn, ack.ts
		ptr = ikcp_encode_seg(ptr, &seg)
	}
	kcp.acklist = kcp.acklist[0:0]

	// 探测窗口大小(如果远端窗口大小为0)

	// 探测远端窗口大小

	// 告知远端窗口大小

	// 计算拥塞窗口大小
	cwnd = _imin_(kcp.snd_wnd, kcp.rmt_wnd)
	if 0 == kcp.nocwnd {
		cwnd = _imin_(kcp.cwnd, cwnd)
	}

	// 将数据从snd_queue移动到snd_buf
	for p := kcp.snd_queue.Front(); p != nil; {
		// 分片编号不在发送窗口内 break
		if _itimediff_(kcp.snd_nxt, kcp.snd_una + kcp.cwnd) >= 0{
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
				
			} else {

			}
			segment.resendts = current + segment.rto

			// 丢包
			lost = true
		} else if segment.fastack >= resent {
			needsend = true
			segment.xmit++
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
			need := IKCP_OVERHEAD + segment.len

			if size + need > int32(kcp.mtu) {
				ikcp_output(kcp, buffer, size)
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
		ikcp_output(kcp, buffer, size)
	}

	// change
	if change {
		
	}

	// lost
	if lost {
		
	}

	//cwnd
	if kcp.cwnd < 1 {
		
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
		kcp.ts_flush == kcp.current
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


// func main()  {
// 	a := uint32(5)
// 	b := uint32(8)
// 	c := uint32(10)

// 	fmt.Println(_ibound_(a, b, c))
// }