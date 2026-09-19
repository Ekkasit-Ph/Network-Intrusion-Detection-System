# Model Development Context: Data Cleaning → Training → Tuning

เอกสารนี้เป็น context เสริมจาก `PROJECT.md` เจาะจงสำหรับงานเขียนโค้ด 3 ส่วน: การทำความสะอาดข้อมูล (module 2), การฝึกโมเดล และการปรับจูนไฮเปอร์พารามิเตอร์ (module 3) ของ autoencoder บนชุดข้อมูล NF-ToN-IoT-v2

## กฎที่ต้องยึดถือ (สำคัญ อย่าละเลย)

1. **ห้ามหา threshold หรือเลือกไฮเปอร์พารามิเตอร์จาก test set** — ใช้ validation set เท่านั้น (data leakage ทำให้ผลลัพธ์ดูดีเกินจริง)
2. **Train set ต้องเป็น benign (Label=0) ล้วน** — ห้ามให้โมเดลเห็นข้อมูล attack ระหว่างฝึก
3. **Fit scaler บน train set เท่านั้น** แล้วเซฟไว้ใช้ transform กับ val/test/inference — ห้าม fit ใหม่กับ val/test
4. **อย่าเลือกไฮเปอร์พารามิเตอร์จาก training loss อย่างเดียว** — เพราะเป็น unsupervised, loss ต่ำอาจแปลว่า latent ใหญ่เกินไปจนโมเดลจำได้ทุกอย่างรวมถึงความผิดปกติ (overfitting) ต้องใช้ label บน validation set มาวัดว่าโมเดลแยก benign/attack ได้ดีแค่ไหน (ดูหัวข้อ "เกณฑ์เลือกไฮเปอร์พารามิเตอร์")
5. **ตัดคอลัมน์ identifier ก่อนป้อนเข้าโมเดล**: `IPV4_SRC_ADDR`, `IPV4_DST_ADDR`, `L4_SRC_PORT`, `L4_DST_PORT` — เก็บแยกไว้ต่างหากสำหรับ join กลับตอนบันทึกผลลง dashboard เท่านั้น

## 1. Data cleaning (module 2)

### Input
ไฟล์ CSV ของ NF-ToN-IoT-v2 (คอลัมน์: 43 ฟีเจอร์ + `Label` + `Attack`) — ดูรายชื่อฟีเจอร์เต็มใน `PROJECT.md`

### ขั้นตอนที่ต้องทำ

1. **ตรวจสอบและจัดการค่า missing/inf/NaN**
   - คอลัมน์ throughput (`SRC_TO_DST_AVG_THROUGHPUT`, `DST_TO_SRC_AVG_THROUGHPUT`) อาจมีค่า `inf` เมื่อ `FLOW_DURATION_MILLISECONDS = 0` — แทนที่ `inf`/`-inf` ด้วย 0 หรือ cap ที่ percentile 99
   - คอลัมน์เฉพาะโปรโตคอล (`ICMP_TYPE`, `ICMP_IPV4_TYPE`, `DNS_QUERY_ID`, `DNS_QUERY_TYPE`, `DNS_TTL_ANSWER`, `FTP_COMMAND_RET_CODE`) จะเป็น 0 หรือค่าว่างสำหรับโฟลว์ที่ไม่ใช่โปรโตคอลนั้น — ตรวจสอบก่อนว่าข้อมูลจริงใช้ 0 หรือ NaN แทน "ไม่มีข้อมูล" แล้ว fillna(0) ให้สอดคล้อง
2. **ลบแถวซ้ำ** (`df.duplicated()`) — NetFlow export มักมีโฟลว์ซ้ำจากการ aggregate หลายจุด
3. **จัดการฟีเจอร์เชิงหมวดหมู่**
   - `PROTOCOL`, `L7_PROTO` — cardinality ต่ำ พิจารณา one-hot encoding (เช็คจำนวนค่าที่ไม่ซ้ำก่อนตัดสินใจ ถ้า >20 ค่า ให้ใช้ frequency encoding แทนเพื่อไม่ให้มิติข้อมูลบวมเกินไป)
   - `TCP_FLAGS`, `CLIENT_TCP_FLAGS`, `SERVER_TCP_FLAGS` — เป็น bitmask ให้เก็บเป็นตัวเลข scaled ตามปกติ ไม่ต้อง one-hot (ทดลอง decompose เป็นบิตแยกได้ในภายหลังถ้าต้องการวิเคราะห์ SHAP ที่ระดับ flag)
4. **ลด skew ของฟีเจอร์เชิงปริมาณ** — คอลัมน์ bytes/packets/duration/throughput มักมีการกระจายแบบเบ้ขวารุนแรง ใช้ `np.log1p()` ก่อนทำ standardization: `IN_BYTES`, `OUT_BYTES`, `IN_PKTS`, `OUT_PKTS`, `FLOW_DURATION_MILLISECONDS`, `SRC_TO_DST_SECOND_BYTES`, `DST_TO_SRC_SECOND_BYTES`, `SRC_TO_DST_AVG_THROUGHPUT`, `DST_TO_SRC_AVG_THROUGHPUT`, `LONGEST_FLOW_PKT`, `SHORTEST_FLOW_PKT`, `MIN_IP_PKT_LEN`, `MAX_IP_PKT_LEN`
5. **แบ่งข้อมูล 3 ส่วน** (ทำหลังทำความสะอาดเสร็จ):
   - `train`: สุ่มจากแถวที่ `Label == 0` เท่านั้น (เช่น 70% ของ benign ทั้งหมด)
   - `val`: benign ที่เหลือ (15%) + สุ่มตัวอย่าง stratified จากทุกคลาส attack ตามสัดส่วนจริง (เพื่อให้คลาสหายากอย่าง Ransomware ยังมีตัวแทนอยู่)
   - `test`: benign ที่เหลือ (15%) + attack ส่วนที่เหลือทั้งหมดที่ยังไม่เคยใช้
   - แนะนำใช้ `sklearn.model_selection.train_test_split(..., stratify=Attack_column)` สำหรับส่วน val/test เพื่อรักษาสัดส่วนคลาส
6. **Fit `StandardScaler`** (หรือ `RobustScaler` ถ้ายังมี outlier เยอะหลัง log-transform) บนฟีเจอร์ตัวเลขของ `train` เท่านั้น แล้ว `joblib.dump()` เก็บไว้
7. **บันทึกผลลัพธ์**: `train.parquet`, `val.parquet`, `test.parquet`, `scaler.pkl`, และไฟล์ `preprocessing_report.json` สรุปสถิติ (จำนวนแถวก่อน/หลังลบซ้ำ, จำนวน missing ที่เจอ, สัดส่วนคลาสในแต่ละ split)

## 2. Model architecture (module 3)

```python
# ตัวอย่างโครงสร้าง — ปรับ hidden dims ตามผลการทดลอง tuning
class Autoencoder(nn.Module):
    def __init__(self, input_dim: int, latent_dim: int, hidden_dims: list[int]):
        super().__init__()
        encoder_layers = []
        dims = [input_dim] + hidden_dims + [latent_dim]
        for i in range(len(dims) - 1):
            encoder_layers += [nn.Linear(dims[i], dims[i+1]), nn.ReLU()]
        self.encoder = nn.Sequential(*encoder_layers[:-1])  # ไม่ใส่ ReLU ที่ latent layer

        decoder_layers = []
        rev_dims = [latent_dim] + hidden_dims[::-1] + [input_dim]
        for i in range(len(rev_dims) - 1):
            decoder_layers += [nn.Linear(rev_dims[i], rev_dims[i+1])]
            if i < len(rev_dims) - 2:
                decoder_layers.append(nn.ReLU())
        self.decoder = nn.Sequential(*decoder_layers)  # เอาต์พุตสุดท้ายไม่มี activation (reconstruct ค่า standardized)

    def forward(self, x):
        z = self.encoder(x)
        x_hat = self.decoder(z)
        return x_hat, z
```

- **Loss**: `nn.MSELoss(reduction='none')` แล้ว `.mean(dim=1)` เพื่อให้ได้ reconstruction error ต่อแถว (ต้องใช้ค่านี้ทั้งสำหรับ backprop และสำหรับคำนวณ anomaly score ตอน inference)
- **Optimizer**: Adam, lr เริ่มต้น 1e-3, ใช้ `ReduceLROnPlateau` monitor validation loss
- **Early stopping**: monitor validation reconstruction error เฉพาะแถว benign ใน val set, patience ~10 epochs
- **Batch size**: เริ่มที่ 256; ถ้าใช้ข้อมูลเต็ม 16.9M แถวและเครื่องจำกัด RAM/GPU ให้พิจารณาสุ่ม subsample benign มาฝึก (เช่น 1-2 ล้านแถว) แทนใช้ทั้งหมด — บันทึกจำนวนที่ใช้จริงไว้ใน config เพื่อรายงานในเล่ม
- **Device**: ใช้ `torch.device('cuda' if torch.cuda.is_available() else 'cpu')` แต่ต้องรัน benchmark บน CPU-only ด้วยอย่างน้อยหนึ่งรอบ เพราะโครงงานอ้างว่าระบบต้องรันบนเกตเวย์ทรัพยากรจำกัด (หัวข้อ 5.7.5)

## 3. Hyperparameter tuning

### พารามิเตอร์ที่ต้องทดลอง (grid หรือ random search)

| พารามิเตอร์ | ช่วงค่าที่ทดลอง | เหตุผล |
|---|---|---|
| `latent_dim` | [4, 8, 16, 24, 32] | Song et al. (2021) ชี้ว่าเป็นปัจจัยวิกฤตที่สุด — ต้อง sweep ให้ครอบคลุม |
| `hidden_dims` | เช่น `[32]`, `[32,16]`, `[64,32]` | ความลึกของโครงข่าย |
| `learning_rate` | [1e-2, 1e-3, 1e-4] | |
| `batch_size` | [128, 256, 512] | |
| `dropout` | [0, 0.1, 0.2] (ใส่ระหว่าง encoder layers) | กันการ overfit ถ้า latent ใหญ่ |

ไม่จำเป็นต้องใช้ไลบรารี AutoML หนัก (Optuna เป็นตัวเลือกได้ถ้าต้องการ) — grid/random search แบบ loop ธรรมดาเพียงพอสำหรับขอบเขตนี้ และอธิบายในรายงานได้ง่ายกว่า

### เกณฑ์เลือกไฮเปอร์พารามิเตอร์ (สำคัญ)

**ห้ามเลือกจาก validation reconstruction loss ต่ำสุดอย่างเดียว** ให้คำนวณ **ROC-AUC** โดยใช้ reconstruction error เป็น anomaly score เทียบกับ label จริงของ validation set (`Label` คอลัมน์) แทน — โมเดลที่ดีที่สุดคือโมเดลที่ค่า reconstruction error ของ benign กับ attack แยกจากกันชัดเจนที่สุด (AUC สูงสุด) ไม่ใช่โมเดลที่ reconstruct ได้แม่นที่สุดโดยรวม

```python
from sklearn.metrics import roc_auc_score

def validation_score(model, val_loader, val_labels):
    errors = compute_reconstruction_errors(model, val_loader)  # array ต่อแถว
    return roc_auc_score(val_labels, errors)  # labels: 1 = attack, ใช้เป็น "ยิ่งerror สูงยิ่งน่าจะเป็น attack"
```

บันทึกผลของทุก config ที่ทดลองลงตาราง (`tuning_results.csv`: latent_dim, hidden_dims, lr, batch_size, dropout, val_auc, val_loss) เพื่อใช้ทำตารางเปรียบเทียบในรายงานหัวข้อ 5.7

## 4. Threshold determination (ต่อจากโมเดลที่เลือกแล้ว)

หลังเลือกไฮเปอร์พารามิเตอร์ที่ดีที่สุดจาก validation AUC แล้ว:

1. คำนวณ reconstruction error ของ **เฉพาะแถว benign** ใน validation set
2. หา threshold ที่ percentile 90, 95, 97, 99 ของค่าดังกล่าว (percentile-based, วิธีหลัก)
3. เปรียบเทียบกับ Gaussian KDE-based threshold (`scipy.stats.gaussian_kde` fit บนค่า reconstruction error ของ benign แล้วหาจุดตัดที่เหมาะสมกับการกระจายของ attack ใน validation set)
4. เลือก threshold สุดท้ายโดยดู ROC curve / Precision-Recall curve บน validation set (ทั้งชุด benign+attack) — ให้น้ำหนัก recall สูงกว่า precision เล็กน้อยตามที่ระบุใน `PROJECT.md` (ระบบเป็น post-hoc verification ไม่ auto-block)
5. **ประเมินผลสุดท้ายบน test set เพียงครั้งเดียว** ด้วย threshold ที่เลือกไว้แล้ว ห้ามย้อนกลับไปปรับ threshold จากผล test

## 5. Artifacts ที่ต้องบันทึกเมื่อจบขั้นตอนนี้

```
artifacts/
├── preprocessing/
│   ├── scaler.pkl             # StandardScaler ที่ fit จาก train
│   └── categorical_encoders.json
└── models/
    └── default/                # ตั้งชื่อ version อื่นได้ผ่าน --artifacts-dir (ดู artifacts/models/README.md)
        ├── model.pt              # state_dict ของโมเดลที่ดีที่สุด
        ├── model_config.json     # {latent_dim, hidden_dims, lr, batch_size, dropout}
        ├── threshold.json        # {method: "percentile", value: ..., percentile: 97}
        ├── tuning_results.csv    # ผลทุก config ที่ทดลอง
        ├── training_history.json # loss ต่อ epoch (train/val) สำหรับพล็อตกราฟ
        └── metrics_report.json   # accuracy, precision, recall, F1, FPR (macro + per-class) บน test set
```

โมเดลและ scaler ในโฟลเดอร์นี้คือสิ่งที่ backend (FastAPI, module 5) และโมดูล SHAP (module 4) จะโหลดไปใช้งานจริงตอน inference — ต้อง freeze/version ไว้ให้ backend อ้างอิง path เดียวกันได้ (ดู `DEFAULT_MODEL_DIR` / `PREPROCESSING_ARTIFACTS_DIR` ใน `source/common/paths.py`)

## 6. โครงสร้างโค้ดที่แนะนำ

```
source/
├── preprocessing/
│   ├── clean.py          # ขั้นตอนที่ 1 (missing/inf/duplicate/log-transform)
│   ├── split.py           # แบ่ง train/val/test
│   └── scale.py           # fit/transform StandardScaler
├── model/
│   ├── autoencoder.py     # class Autoencoder
│   ├── train.py           # training loop + early stopping
│   ├── tune.py             # hyperparameter sweep + AUC-based selection
│   ├── threshold.py        # percentile + KDE threshold, ROC/PR analysis
│   └── evaluate.py         # metrics บน test set
└── configuration/
    └── search_space.yaml   # grid ของไฮเปอร์พารามิเตอร์ในหัวข้อ 3
```
