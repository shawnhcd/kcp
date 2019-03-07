// Package kcp - A Fast and Reliable ARQ Protocol
package main

import (
	"encoding/binary"
	//"container/list"
	"fmt"
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
	snd_queue *list.List
	rcv_queue *list.List
	snd_buf *list.List
	rcv_buf *list.List

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



func main()  {
	a := uint32(5)
	b := uint32(8)
	c := uint32(10)

	fmt.Println(_ibound_(a, b, c))
}