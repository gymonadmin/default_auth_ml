// src/entities/profile.ts
import {
  Entity,
  PrimaryGeneratedColumn,
  Column,
  CreateDateColumn,
  UpdateDateColumn,
  Index,
} from 'typeorm';

@Entity('profiles')
@Index('profiles_user_id_unique', ['userId'], { unique: true })
@Index('idx_profiles_deleted_at', ['deletedAt'])
export class Profile {
  @PrimaryGeneratedColumn('uuid')
  id!: string;

  @Column({ 
    type: 'uuid', 
    nullable: false 
  })
  userId!: string;

  @Column({ 
    type: 'varchar', 
    length: 50, 
    nullable: false 
  })
  firstName!: string;

  @Column({ 
    type: 'varchar', 
    length: 50, 
    nullable: false 
  })
  lastName!: string;

  @Column({ 
    type: 'timestamptz', 
    nullable: true 
  })
  deletedAt!: Date | null;

  @CreateDateColumn({ 
    type: 'timestamptz',
    default: () => 'CURRENT_TIMESTAMP'
  })
  createdAt!: Date;

  @UpdateDateColumn({ 
    type: 'timestamptz',
    default: () => 'CURRENT_TIMESTAMP'
  })
  updatedAt!: Date;

  // NO RELATIONSHIPS DEFINED HERE
  // We'll handle relationships through queries instead

  // Computed properties
  get fullName(): string {
    return `${this.firstName} ${this.lastName}`.trim();
  }

  get initials(): string {
    const firstInitial = this.firstName.charAt(0).toUpperCase();
    const lastInitial = this.lastName.charAt(0).toUpperCase();
    return `${firstInitial}${lastInitial}`;
  }

  get isDeleted(): boolean {
    return this.deletedAt !== null;
  }

  get isActive(): boolean {
    return this.deletedAt === null;
  }

  // Methods
  updateName(firstName: string, lastName: string): void {
    this.firstName = firstName.trim();
    this.lastName = lastName.trim();
  }

  markAsDeleted(): void {
    this.deletedAt = new Date();
  }

  restore(): void {
    this.deletedAt = null;
  }
}
