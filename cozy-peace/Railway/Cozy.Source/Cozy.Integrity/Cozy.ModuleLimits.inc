{ Finite measurement resource limits, not trust decisions. All values are
  bytes. Own A/B/O artifacts keep their existing limits. The larger profile
  is used only for explicit current-process module inventory plans. The same
  absolute scan deadline/cancellation still covers every phase of a snapshot. }
  OwnPeFileLimit: UInt64 = 64 * 1024 * 1024;
  OwnPeImageLimit: UInt64 = 128 * 1024 * 1024;
  OwnPeCodeLimit: UInt64 = 64 * 1024 * 1024;
  InventoryPeFileLimit: UInt64 = 512 * 1024 * 1024;
  InventoryPeImageLimit: UInt64 = 1024 * 1024 * 1024;
  InventoryPeCodeLimit: UInt64 = 256 * 1024 * 1024;
  InventoryFileBudget: Int64 = Int64(2) * 1024 * 1024 * 1024;
  InventoryCodeBudget: Int64 = 512 * 1024 * 1024;
