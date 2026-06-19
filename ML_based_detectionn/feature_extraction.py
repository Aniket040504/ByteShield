import pefile
import pandas as pd
import math


def calculate_entropy(data):
    if not data:
        return 0
    entropy = 0
    for x in range(256):
        p_x = float(data.count(bytes([x]))) / len(data)
        if p_x > 0:
            entropy += - p_x * math.log(p_x, 2)
    return entropy


def extract_features(file_path):
    try:
        pe = pefile.PE(file_path)
    except pefile.PEFormatError:
        return None  # Not a valid PE file

    # ── Section-level calculations ──────────────────────────────────────────
    section_entropies = []
    section_characteristics = []

    for section in pe.sections:
        section_entropies.append(calculate_entropy(section.get_data()))
        section_characteristics.append(section.Characteristics)

    section_min_entropy = min(section_entropies) if section_entropies else 0
    # SectionMaxChar = max Characteristics value across all sections
    # (matches the dataset — values like 3758096608, NOT section count)
    section_max_char = max(section_characteristics) if section_characteristics else 0

    # ── Directory entries ────────────────────────────────────────────────────
    has_export = 1 if hasattr(pe, 'DIRECTORY_ENTRY_EXPORT') else 0
    has_import = 1 if hasattr(pe, 'DIRECTORY_ENTRY_IMPORT') else 0

    image_dir_entry_export = pe.OPTIONAL_HEADER.DATA_DIRECTORY[0].Size if has_export else 0
    directory_entry_import_size = pe.OPTIONAL_HEADER.DATA_DIRECTORY[1].Size if has_import else 0

    # ── Build the exact 22 features the model was trained on ────────────────
    features = {
        'MajorSubsystemVersion':        pe.OPTIONAL_HEADER.MajorSubsystemVersion,
        'MinorOperatingSystemVersion':  pe.OPTIONAL_HEADER.MinorOperatingSystemVersion,
        'MajorOperatingSystemVersion':  pe.OPTIONAL_HEADER.MajorOperatingSystemVersion,
        'Subsystem':                    pe.OPTIONAL_HEADER.Subsystem,
        'SizeOfStackReserve':           pe.OPTIONAL_HEADER.SizeOfStackReserve,
        'TimeDateStamp':                pe.FILE_HEADER.TimeDateStamp,
        'MinorSubsystemVersion':        pe.OPTIONAL_HEADER.MinorSubsystemVersion,
        'MinorImageVersion':            pe.OPTIONAL_HEADER.MinorImageVersion,
        'MajorLinkerVersion':           pe.OPTIONAL_HEADER.MajorLinkerVersion,
        'DirectoryEntryExport':         has_export,
        'ImageBase':                    pe.OPTIONAL_HEADER.ImageBase,
        'DllCharacteristics':           pe.OPTIONAL_HEADER.DllCharacteristics,
        'Characteristics':              pe.FILE_HEADER.Characteristics,
        'DirectoryEntryImportSize':     directory_entry_import_size,
        'SectionMaxChar':               section_max_char,
        'SizeOfHeaders':                pe.OPTIONAL_HEADER.SizeOfHeaders,
        'MajorImageVersion':            pe.OPTIONAL_HEADER.MajorImageVersion,
        'SizeOfInitializedData':        pe.OPTIONAL_HEADER.SizeOfInitializedData,
        'CheckSum':                     pe.OPTIONAL_HEADER.CheckSum,
        'ImageDirectoryEntryExport':    image_dir_entry_export,
        'AddressOfEntryPoint':          pe.OPTIONAL_HEADER.AddressOfEntryPoint,
        'SectionMinEntropy':            section_min_entropy,
    }

    return pd.DataFrame([features])
