P4C = p4c-bm2-ss
P4SRC = p4src/flare_sffp.p4
OUT_JSON = configs/bmv2.json
OUT_P4INFO = configs/p4info.txt

build:
	$(P4C) --arch v1model -o $(OUT_JSON) \
	       --p4runtime-files $(OUT_P4INFO) --p4runtime-format text \
	       $(P4SRC)

clean:
	rm -f $(OUT_JSON) $(OUT_P4INFO)
