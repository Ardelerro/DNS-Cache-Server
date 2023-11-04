package main

import (
	"encoding/binary"
	"encoding/json"
	"fmt"
	"math/rand"
	"net"
	"strings"
	"time"

	"github.com/go-redis/redis/v8"
	"golang.org/x/net/context"
)

const (
	dnsServer      = "8.8.8.8:53"     // Google's Public DNS server
	redisCacheAddr = "localhost:6379" // Redis server address
	redisKeyPrefix = "dns_cache:"
)

var redisClient *redis.Client

func main() {
	redisClient = createRedisClient()
	defer redisClient.Close()
	redisClient.FlushDB(redisClient.Context())

	udpAddr, err := net.ResolveUDPAddr("udp", ":53")
	if err != nil {
		fmt.Println("Error resolving UDP address:", err)
		return
	}

	udpConn, err := net.ListenUDP("udp", udpAddr)
	if err != nil {
		fmt.Println("Error creating UDP connection:", err)
		return
	}
	defer udpConn.Close()

	fmt.Println("DNS caching server is listening on :53")

	handleDNSQuery(udpConn)
}

func handleDNSQuery(conn *net.UDPConn) {

	buf := make([]byte, 512) // DNS packet size limit is 512 bytes

	for {
		n, addr, err := conn.ReadFromUDP(buf)

		if err != nil {
			fmt.Printf("Error reading DNS query: %v\n", err)
			continue
		}

		query := buf[:n]

		hostname, err := extractHostname(query)
		if err != nil {
			fmt.Printf("Error extracting hostname: %v\n", err)
			continue
		}

		fmt.Printf("Received DNS query for %s\n", hostname)

		ipAddress, err := resolveDNSWithCaching(hostname)

		fmt.Printf("Resolved IP addresses: %v\n", ipAddress)

		response := buildDNSResponse(query, ipAddress)

		_, err = conn.WriteToUDP(response, addr)
		if err != nil {
			fmt.Printf("Error sending DNS response: %v\n", err)
		}
	}
}

func buildDNSResponse(query []byte, ipAddresses []net.IP) []byte {

	response := make([]byte, len(query))
	copy(response, query)

	response[2] |= 0x80
	response[3] = 0x00

	answerCount := uint16(len(ipAddresses))
	binary.BigEndian.PutUint16(response[6:8], answerCount)

	for _, ip := range ipAddresses {
		answer := make([]byte, 16)
		answer[0] = 0xC0
		answer[1] = 0x0C
		answer[2] = 0x00
		answer[3] = 0x01
		answer[4] = 0x00
		answer[5] = 0x01
		answer[6] = 0x00
		answer[7] = 0x00
		answer[8] = 0x00
		answer[9] = 0x00

		binary.BigEndian.PutUint16(answer[10:12], uint16(4))

		ipBytes := ip.To4()
		copy(answer[12:], ipBytes)

		response = append(response, answer...)

	}

	return response
}

func extractHostname(query []byte) (string, error) {

	if len(query) < 12 {
		return "", fmt.Errorf("invalid DNS query: too short")
	}

	offset := 12
	hostnameParts := []string{}

	for query[offset] != 0 {
		labelLen := int(query[offset])
		if offset+1+labelLen > len(query) {
			return "", fmt.Errorf("invalid DNS query: label length exceeds packet size")
		}

		hostnameParts = append(hostnameParts, string(query[offset+1:offset+1+labelLen]))

		offset += 1 + labelLen
	}

	hostname := strings.Join(hostnameParts, ".")

	return hostname, nil
}

func createRedisClient() *redis.Client {
	client := redis.NewClient(&redis.Options{
		Addr:     redisCacheAddr,
		Password: "", // No password
		DB:       0,  // Default DB
	})

	return client
}

func resolveDNSWithCaching(hostname string) ([]net.IP, error) {
	// Check the cache first
	cachedIPs, err := getFromCache(hostname)
	if err != nil {
		fmt.Printf("error reading cache: %v\n", err)
		return nil, err
	}

	if len(cachedIPs) > 0 {
		fmt.Println("DNS resolution result found in cache.")
		return cachedIPs, nil
	}

	// Perform DNS resolution
	ipAddresses, err := resolveDNS(hostname)
	if err != nil {
		return nil, err
	}

	// Cache the resolved IP addresses
	err = cacheIPs(hostname, ipAddresses)
	if err != nil {
		fmt.Printf("Error caching DNS result: %v\n", err)
	}

	return ipAddresses, nil
}

func getFromCache(hostname string) ([]net.IP, error) {
	ctx := context.Background()
	cacheKey := redisKeyPrefix + hostname

	cachedIPs, err := redisClient.Get(ctx, cacheKey).Result()
	if err != nil {
		if err == redis.Nil {
			return nil, nil // Cache miss
		}
		return nil, err
	}

	// Parse the cached IPs
	ipStrings := []string{}
	err = json.Unmarshal([]byte(cachedIPs), &ipStrings)
	if err != nil {
		return nil, err
	}

	ips := make([]net.IP, len(ipStrings))
	for i, ipStr := range ipStrings {
		ips[i] = net.ParseIP(ipStr)
	}

	return ips, nil
}

func cacheIPs(hostname string, ipAddresses []net.IP) error {
	ctx := context.Background()
	cacheKey := redisKeyPrefix + hostname

	ipStrings := make([]string, len(ipAddresses))
	for i, ip := range ipAddresses {
		ipStrings[i] = ip.String()
	}

	ipStringsJSON, err := json.Marshal(ipStrings)
	if err != nil {
		return err
	}

	err = redisClient.Set(ctx, cacheKey, ipStringsJSON, 24*time.Hour).Err()
	if err != nil {
		return err
	}

	return nil
}

func resolveDNS(hostname string) ([]net.IP, error) {
	// Create a UDP connection to the DNS server
	conn, err := net.Dial("udp", dnsServer)

	if err != nil {
		return nil, err
	}

	defer conn.Close()

	// Prepare the DNS query message
	queryMsg := buildDNSQuery(hostname)

	// Send the DNS query to the server
	_, err = conn.Write(queryMsg)
	if err != nil {
		return nil, err
	}

	response := make([]byte, 1024)

	// Read the DNS response from the server
	n, err := conn.Read(response)
	if err != nil {
		return nil, err
	}

	// Check for DNS response header errors
	err = checkDNSResponseHeader(response[:n])
	if err != nil {
		return nil, err
	}

	// Parse the DNS response
	ipAddresses, err := parseDNSResponse(response[:n])
	if err != nil {
		return nil, err
	}

	return ipAddresses, nil
}

func buildDNSQuery(hostname string) []byte {

	rand.Seed(time.Now().UnixNano())

	// Generate a query ID (16 bits)
	queryID := uint16(rand.Uint32())

	flags := uint16(0x0100) // Standard query (QR=0, OPCODE=0, AA=0, TC=0, RD=1)

	// Set the number of questions in the DNS message (16 bits)
	numQuestions := uint16(1)

	// Build the DNS query message
	dnsQuery := make([]byte, 12)
	dnsQuery[0] = byte(queryID >> 8)
	dnsQuery[1] = byte(queryID)
	dnsQuery[2] = byte(flags >> 8)
	dnsQuery[3] = byte(flags)
	dnsQuery[4] = byte(numQuestions >> 8)
	dnsQuery[5] = byte(numQuestions)

	// Add the domain name to the DNS query message (QNAME)
	domainParts := []string{}
	for _, part := range splitDomain(hostname) {
		domainParts = append(domainParts, string([]byte{byte(len(part))})+part)
	}
	domainParts = append(domainParts, "\x00")
	qname := []byte{}
	for _, part := range domainParts {
		qname = append(qname, []byte(part)...)
	}

	dnsQuery = append(dnsQuery, qname...)
	dnsQuery = append(dnsQuery, 0x00, 0x01) // QTYPE (A record type)
	dnsQuery = append(dnsQuery, 0x00, 0x01) // QCLASS (IN class)

	return dnsQuery
}

func checkDNSResponseHeader(response []byte) error {

	// Check the DNS response header for errors
	if len(response) < 12 {
		return fmt.Errorf("invalid DNS response: too short")
	}

	// Check the response code (RCODE)
	rcode := response[3] & 0x0F
	switch rcode {
	case 0: // No error
		return nil
	case 1: // Format error
		return fmt.Errorf("DNS response format error")
	case 2: // Server failure
		return fmt.Errorf("DNS server failure")
	case 3: // Name Error (host does not exist)
		return fmt.Errorf("DNS name not found")
	case 4: // Not implemented (the server does not support the requested query)
		return fmt.Errorf("DNS query type not implemented")
	case 5: // Refused (the server refused the request)
		return fmt.Errorf("DNS query refused by the server")
	default:
		return fmt.Errorf("unknown DNS response code: %d", rcode)
	}

}

func parseDNSResponse(response []byte) ([]net.IP, error) {

	answerOffset := skipDNSHeader(response) + skipQuerySection(response)

	ipAddresses := []net.IP{}

	ip := net.IP(response[answerOffset : answerOffset+4])
	ipAddresses = append(ipAddresses, ip)

	return ipAddresses, nil

}

func skipDNSHeader(response []byte) int {
	return 12
}

func splitDomain(domain string) []string {
	return strings.Split(domain, ".")
}

// skipQuerySection skips the query section and returns the offset where the answer section starts
func skipQuerySection(response []byte) int {
	offset := 12
	questions := int(binary.BigEndian.Uint16(response[4:6]))

	for i := 0; i < questions; i++ {
		for response[offset] != 0 {
			offset++
		}
		offset += 4 // Question type and class
	}
	return offset + 1
}
