# PKS_Zadanie 1

To print out help run

```bash
python main.py -h
```
To execute analyzer on a .pcap file run
```bash
python main.py -f "./samples/trace-26.pcap"
```
To run and test all PCAP files within a folder run
```bash
python main.py --test "./samples" --validator-path 
"./validator.py" --schema-path "./schemas/schema-all-with-unknown.yaml"
```
Filter out protocol
```bash
python main.py -f "./samples/trace-25.pcap" -p HTTP
```


## Used libraries
* [pypcap](https://pypi.org/project/pypcap/)
* [ruamel](https://pypi.org/project/ruamel.yaml/)