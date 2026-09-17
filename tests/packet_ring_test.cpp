#include "common/packet_ring.h"
#include <atomic>
#include <fstream>
#include <future>
#include <iostream>
#include <set>
#include <sstream>
#include <thread>

namespace {
void Check(bool pass, const char* error) { if (!pass) throw std::runtime_error(error); }
std::shared_ptr<const wpe::PendingPacket> Packet(std::int64_t id, int raw=1, int mode=1, int modified=1) {
    auto packet=std::make_shared<wpe::PendingPacket>(); packet->id=id;
    if(raw>=0) packet->raw=std::make_shared<const wpe::ByteBuffer>(static_cast<std::size_t>(raw));
    if(mode==1) packet->modified=packet->raw;
    else if(mode==2 && modified>=0) packet->modified=std::make_shared<const wpe::ByteBuffer>(static_cast<std::size_t>(modified));
    return packet;
}
std::vector<std::string> Split(const std::string& line) {
    std::vector<std::string> fields;
    std::size_t pos=0;
    for(;;) { const auto end=line.find('\t',pos); fields.push_back(line.substr(pos,end==std::string::npos?end:end-pos)); if(end==std::string::npos) return fields; pos=end+1; }
}
void Edges() {
    wpe::PacketRing ring(2,128);
    ring.Enqueue(nullptr); Check(ring.Count()==0,"Null enqueue");
    ring.Enqueue(Packet(1)); ring.Enqueue(Packet(2));
    Check(ring.Count()==1 && ring.Dropped()==1,"Byte capacity evicts oldest");
    ring.Enqueue(Packet(3,1000));
    auto batch=ring.DequeueBatch(9,1,std::chrono::milliseconds(0));
    Check(batch.size()==1 && batch[0]->id==3 && ring.Dropped()==2,"Oversized packet kept and taken across byte budget");
    ring.Clear(); Check(ring.Dropped()==2,"Clear preserves cumulative drops");
    Check(Packet(1,10,1)->Size()==74 && Packet(1,10,2,10)->Size()==84,"Alias identity controls byte accounting");
    auto waiter=std::async(std::launch::async,[&] { return ring.DequeueBatch(10,1024,std::chrono::seconds(5)); });
    for(int attempt=0;attempt<100 && waiter.wait_for(std::chrono::milliseconds(5))!=std::future_status::ready;++attempt)ring.Wake();
    Check(waiter.wait_for(std::chrono::seconds(2))==std::future_status::ready,"Wake releases blocked consumer");
    Check(waiter.get().empty(),"Wake does not invent a packet");
    wpe::PacketRing concurrent(64,4096);
    constexpr int per_producer=5000;
    std::atomic<int> finished{0};
    std::set<std::int64_t> seen;
    std::jthread first([&] { for(int i=0;i<per_producer;++i) concurrent.Enqueue(Packet(i)); ++finished; concurrent.Wake(); });
    std::jthread second([&] { for(int i=0;i<per_producer;++i) concurrent.Enqueue(Packet(per_producer+i)); ++finished; concurrent.Wake(); });
    while(finished.load()!=2 || concurrent.Count()!=0) {
        for(const auto& item:concurrent.DequeueBatch(32,2048,std::chrono::milliseconds(10)))
            Check(seen.insert(item->id).second,"Duplicate concurrent packet");
    }
    Check(seen.size()+concurrent.Dropped()==2*per_producer,"Concurrent receive/drop conservation");
}
}
int main(int argc,char** argv) {
    std::size_t rows=0;
    try {
        Edges();
        if(argc==2) {
            std::ifstream input(argv[1]); Check(bool(input),"Cannot open ring fixture");
            std::unique_ptr<wpe::PacketRing> ring;
            std::string line;
            while(std::getline(input,line)) {
                if(!line.empty()&&line.back()=='\r') line.pop_back();
                const auto f=Split(line); ++rows;
                if(f.at(0)=="new") ring=std::make_unique<wpe::PacketRing>(std::stoi(f.at(1)),std::stoll(f.at(2)));
                else if(f[0]=="enqueue") {
                    auto packet=Packet(std::stoll(f.at(1)),std::stoi(f.at(2)),std::stoi(f.at(3)),std::stoi(f.at(4)));
                    Check(packet->Size()==std::stoll(f.at(5)),"Original pending size"); ring->Enqueue(packet);
                    Check(ring->Count()==std::stoull(f.at(6))&&ring->Dropped()==std::stoull(f.at(7)),"Original enqueue state");
                } else if(f[0]=="take") {
                    const auto batch=ring->DequeueBatch(std::stoi(f.at(1)),std::stoll(f.at(2)),std::chrono::milliseconds(0));
                    std::string ids; for(const auto& item:batch){if(!ids.empty())ids+=',';ids+=std::to_string(item->id);}
                    Check(ids==f.at(3),"Original dequeue order/budget");
                    Check(ring->Count()==std::stoull(f.at(4))&&ring->Dropped()==std::stoull(f.at(5)),"Original dequeue state");
                } else if(f[0]=="clear") { ring->Clear(); Check(ring->Count()==std::stoull(f.at(1))&&ring->Dropped()==std::stoull(f.at(2)),"Original clear state"); }
                else throw std::runtime_error("Unknown ring fixture");
            }
            Check(input.eof()&&rows==6416,"Complete ring fixture");
        } else Check(argc==1,"Usage: ring-test [vectors.tsv]");
        std::cout<<"PASS: packet ring edges/concurrency; "<<rows<<" original state-transition vectors\n";
        return 0;
    } catch(const std::exception& error){std::cerr<<"FAIL ring row "<<rows<<": "<<error.what()<<'\n';return 1;}
}
